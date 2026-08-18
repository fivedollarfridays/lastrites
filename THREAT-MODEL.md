# Threat model

lastrites handles the most sensitive class of data on a machine —
credentials and the map of where they live. This document states plainly
what it protects against, what it deliberately does not, and where the
sharp edges are. If a claim here stops being true, that is a bug of the
highest severity.

## What lastrites protects against

- **Silent credential death.** A key that stops authenticating and nothing
  notices. The canary layer exists solely to convert silent death into a
  page.
- **Silent watchdog death.** The watcher itself dying quietly — the
  second-order failure that makes every first-order guarantee a lie.
  Heartbeats are capture-based and provenance-stamped; external dead-man
  watching is a first-class deployment requirement, not an option.
- **Half-completed rotation.** The failure mode a rotator *introduces*:
  new key minted, consumers partially updated, old key revoked — an outage
  manufactured by the tool that promised to prevent one. Rotation is
  two-phase with overlap and fails CLOSED: any verification failure halts
  with both keys valid and pages a human.
- **Forgotten copies.** The `.env` on the old laptop path, the crontab
  line from two migrations ago. The credential graph exists to find copies
  you did not remember distributing.

## What lastrites deliberately does NOT protect against

- **A compromised host.** lastrites runs local-first with local
  privileges. An attacker on the box already has what lastrites has. It is
  an availability and hygiene tool, not an intrusion defense.
- **Malicious insiders with the parent credentials.** See blast radius.
- **Secrets it cannot see.** Values inside compiled binaries, OS keychains
  it is not granted, or derived/transformed secrets (base64 wrappers,
  KDF outputs) may evade fingerprint clustering. The graph is honest about
  its own coverage: unscanned surface classes are reported as blind spots,
  never as absence of copies.

## The sharp edges, named

**1. The parent-credential blast radius.** Rotation requires credentials
that can mint credentials (an AWS key with `iam:CreateAccessKey`, a
Cloudflare token that can roll tokens). These parents are the crown
jewels: strictly scoped, stored outside the graph store, never
fingerprinted into it, and their own health is watched by the same canary
machinery. A deployment that gives lastrites broad admin credentials has
misread this document.

**2. Fingerprints are peppered HMACs, never bare hashes.** The graph
stores locations and fingerprints, never values. A bare SHA-256 of a
low-entropy secret is a dictionary attack waiting politely; fingerprints
are HMAC(machine-local pepper, value), with the pepper stored separately
from the graph. Stealing the graph alone yields a map of *where* secrets
live — bad — but not an oracle for *what* they are.

**3. The graph is itself sensitive.** A list of every credential location
on your estate is reconnaissance gold. The graph store is local, encrypted
at rest, and never leaves the machine. Nothing in lastrites phones home;
there is nothing to phone home to.

**4. Escalation channels are part of the attack surface.** A pager that
anyone can write to can drown real alarms in noise (alert fatigue is a
security failure). Deployment docs treat the alerting channel's
authentication with the same seriousness as the credentials themselves.

**5. Scan-surface enumeration must fail loud.** A parser that silently
skips a malformed plist or an unreadable file undercounts the estate and
reports false confidence. Skips are counted, surfaced, and alarmed on —
drift-tolerant parsing, never silent dropping.

## Evidence discipline

Docs in this repo mark claims as **verified** only with the command, the
date, and the observed output attached. Everything else is design intent.
This file contains no verified claims yet: lastrites is in design phase
and this model is the contract the implementation will be held to.
