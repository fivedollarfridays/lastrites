# lastrites

[![CI](https://github.com/fivedollarfridays/lastrites/actions/workflows/ci.yml/badge.svg)](https://github.com/fivedollarfridays/lastrites/actions/workflows/ci.yml)

**your keys die. someone should be there.**

A local-first watchdog for your credential estate: the API keys, OAuth
tokens, and portal secrets scattered across your machines, crontabs,
plists, env files, and SaaS dashboards. lastrites notices them dying —
ideally before they do — and makes sure their death is never silent.

## The thesis

Nearly every credential outage is a **detection failure**, not a rotation
failure. The token that expired three weeks ago and nobody noticed. The
OAuth refresh that died on a Tuesday and took a pipeline with it. The
cron that has been failing auth since the last laptop migration. Vaults
and secret managers rotate what lives inside their walls — but a real
person's estate mostly lives *outside* the walls, and most of it can't be
rotated by any API at all.

lastrites is honest about that. Three verbs, applied per credential by
what its provider actually allows:

| Verb | What it means | Applies to |
|---|---|---|
| **VERIFY** | a canary call proving the credential authenticates *right now*, producing standing evidence | everything |
| **ESCALATE** | expiry ledger + lead-time paging + a guided re-auth runbook | the unrotatable majority: OAuth refresh tokens, portal-only keys |
| **ROTATE** | two-phase overlap rotation (mint → verify → update consumers → verify → grace → revoke), fail-closed at every step | where APIs exist: AWS IAM, GCP SA keys, Cloudflare tokens, self-managed secrets |

## The credential graph

The piece no vault builds: **which consumers hold a copy of which
credential**. lastrites discovers it rather than asking you to declare it —
scanning your config surfaces (crontabs, launchd plists, env files, CI
secrets) and clustering secrets by *local, peppered fingerprint*: identical
fingerprints across locations are the same credential's copies. The graph
is what makes rotation safe (you can't atomically update consumers you
don't know about) and what makes escalation useful (blast radius *before*
you re-auth). Design: [docs/DESIGN-credential-graph.md](docs/DESIGN-credential-graph.md).

## The watcher is watched

A rotator that dies silently is worse than no rotator. lastrites is built
to run under a dead-man triangle: its heartbeats are **capture-based**
(stamped only on verified-working evidence, never on "the process ran")
and **provenance-stamped** (a hand-run check cannot impersonate the
scheduler). It pairs with [deadman](https://github.com/fivedollarfridays/deadman)-style
external watching so the failure of lastrites itself pages you the same
way a dying key does.

## Running it scheduled

`lastrites sweep` is the scheduled entry point: scan the estate, canary
every registered credential, evaluate escalation rules, and — only if all
of that completes — write the capture-based heartbeat described above.

**The environment contract.** A sweep learns who invoked it from a single
env var, `LASTRITES_SCHEDULED`. Its *presence*, not its value, is the
contract — a crontab line only has to export it, not agree with lastrites
on a sentinel value. Absent means interactive; there is no third state.
The heartbeat this writes always carries `invoked_by`, and any reader of
that heartbeat (a deadman-style collector, a freshness monitor rail) must
**fail closed** if the field is missing rather than assume "hand-run" —
per [docs/WATCH-TOPOLOGY.md](docs/WATCH-TOPOLOGY.md), a hand-run sweep must
never be able to impersonate the scheduler.

**Registering credentials to canary.** The graph store never holds a raw
value (see THREAT-MODEL §2/§3), so a sweep needs an explicit,
operator-owned config declaring which fingerprint maps to which provider
and where its raw value lives — the same `--value-env`/`--value-file`
discipline `lastrites canary` enforces on the command line, just declared
once. This file lives outside the repo, next to the pepper and the graph
store:

```json
[
  {
    "fingerprint_prefix": "3f9a2b7c1e4d",
    "provider": "cloudflare",
    "value_env": "LASTRITES_CF_TOKEN"
  }
]
```

**The alert channel.** Escalation fires through a configured *command*,
never a hardcoded endpoint — THREAT-MODEL §4 treats the channel as part
of the attack surface, and the push topic itself is the sensitive
credential (see WATCH-TOPOLOGY). No literal endpoint or topic lives in
this repo, anywhere, enforced by a repo-wide grep-proof test. The channel
config is operator-owned, also outside the repo:

```json
{
  "command": ["curl", "-fsS", "-d", "{message}", "https://ntfy.sh/<your-private-topic>"]
}
```

`{message}` is substituted into every argument that contains it before the
command runs.

**Example crontab line:**

```
LASTRITES_SCHEDULED=1
0 * * * * /usr/local/bin/lastrites sweep \
  --root "$HOME" \
  --store "$HOME/.lastrites/graph.sqlite3" \
  --credentials-config "$HOME/.lastrites/credentials.json" \
  --alert-channel-config "$HOME/.lastrites/channel.json" \
  --heartbeat-file "$HOME/.lastrites/heartbeat.json" \
  >> "$HOME/.lastrites/sweep.log" 2>&1
```

**Install-proof: a scheduled sweep is not installed until it has run
under `env -i` semantics.** Cron gives a job a nearly empty environment —
no inherited `PATH` additions, no exported shell variables from your
`.bashrc` or `.zshrc`. A sweep that only works because your interactive
shell happens to export something will fail silently the first time cron
runs it, and the strict provenance contract means that failure won't even
get *misread* as a successful hand-run — it just won't run at all. Before
trusting a crontab line, run it once by hand with the environment cron
would actually give it:

```bash
env -i LASTRITES_SCHEDULED=1 PATH=/usr/bin:/bin HOME="$HOME" \
  /usr/local/bin/lastrites sweep \
  --root "$HOME" \
  --store "$HOME/.lastrites/graph.sqlite3" \
  --credentials-config "$HOME/.lastrites/credentials.json" \
  --alert-channel-config "$HOME/.lastrites/channel.json" \
  --heartbeat-file "$HOME/.lastrites/heartbeat.json"
```

If this fails, the crontab line will fail identically — better to find
that out now than to wait for the dead-man layer to notice a stale
heartbeat. Only once this has been run successfully under `env -i` is the
schedule considered installed, not just written.

## Threat model conformance

Every sharp edge in [THREAT-MODEL.md](THREAT-MODEL.md) is executable: the
conformance test suite in [`tests/test_threat_model_conformance.py`](tests/test_threat_model_conformance.py)
maps every named section and principle to at least one test, referenced by
section number. The public repo ships only commits that pass their own doctrine.

**Verified sections** (see [THREAT-MODEL.md](THREAT-MODEL.md) for evidence):

- **§1, §3**: File permissions (0600) and at-rest posture (SQLite, WAL, no raw values on disk)
- **§2**: Peppered fingerprints (HMAC, no bare hashes)
- **§4**: Escalation channels (no hardcoded endpoints, configured externally)
- **§5**: Scan-surface enumeration (skip loudness, no silent dropping)
- **§6**: Canary verdict vocabulary (401/403 only → DEAD, others → UNOBSERVABLE)
- **§7**: Sweep heartbeat and escalation (capture-based, provenance-stamped with `invoked_by`)

CI enforces these gates on every push/PR, and a finding in any of them
fails the build (no `continue-on-error`):

```bash
pytest -n auto --dist=worksteal          # Conformance + all tests green
ruff check . && ruff format --check .     # Code quality
```

Secret scanning runs as a separate required job using the official
SHA-pinned `gitleaks/gitleaks-action` (gitleaks is a Go binary and is
**not** installed from PyPI — a `pip install gitleaks` line would pull an
unaffiliated squatter). See [.github/workflows/ci.yml](.github/workflows/ci.yml).

## Status

Design phase. Detection and escalation ship first — a read-only canary
daemon cannot hurt the estate it watches. Rotation lands after the
detection layer has survived its author's own credentials for a while.

Threat model: [THREAT-MODEL.md](THREAT-MODEL.md) — read it before trusting
this with anything. Claims in these docs follow an evidence discipline:
if a doc says "verified," it names what was run and when.

## License

MIT.
