"""`lastrites` command line.

The load-bearing behaviour is the exit code on an empty scan. A scan that
opened zero surfaces found zero credentials, and so does a scan of a
genuinely clean machine -- identical output, opposite meanings. Silence
gets its own nonzero exit so no cron wrapper can mistake one for the other.

`sweep`'s subparser and command handler live in `lastrites/sweep/cli.py`,
not here -- this file stays at the "scan and canary" surface it started
with, under its own architecture limits.
"""

from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from lastrites.canary.engine import run_probe
from lastrites.canary.providers import PROVIDERS, get_provider
from lastrites.canary.report import render_json as render_canary_json
from lastrites.canary.report import render_text as render_canary_text
from lastrites.canary.models import Verdict
from lastrites.core.fingerprint import fingerprint
from lastrites.core.pepper import DEFAULT_PEPPER_PATH, load_or_create_pepper
from lastrites.core.store import GraphStore
from lastrites.scan.discovery import resolve_targets
from lastrites.scan.estate import scan_estate
from lastrites.scan.persist import persist
from lastrites.scan.report import render_json, render_text
from lastrites.sweep.cli import add_sweep_subparser, run_sweep_command

EXIT_OK = 0
EXIT_NO_SURFACES = 2
EXIT_NOTHING_READABLE = 3
EXIT_STORE_FAILED = 4

EXIT_CANARY_ALIVE = 0
EXIT_CANARY_DEAD = 1
EXIT_CANARY_UNOBSERVABLE = 2
EXIT_CANARY_NOT_FOUND = 3
EXIT_CANARY_AMBIGUOUS = 4
EXIT_CANARY_MISMATCH = 5
EXIT_CANARY_VALUE_UNREADABLE = 6
EXIT_CANARY_BAD_CONFIG = 7

_CANARY_EXIT_BY_VERDICT = {
    Verdict.ALIVE: EXIT_CANARY_ALIVE,
    Verdict.DEAD: EXIT_CANARY_DEAD,
    Verdict.UNOBSERVABLE: EXIT_CANARY_UNOBSERVABLE,
}

NO_SURFACES_ALARM = (
    "ALARM: no surfaces were scanned. This is not a clean estate -- it is an "
    "unscanned one. Check the --root/--crontab/--plist/--env-file targets."
)
NOTHING_READABLE_ALARM = (
    "ALARM: every surface attempted was unreadable. 'Credentials found: 0' here "
    "means the scanner saw nothing, not that there is nothing to see."
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lastrites", description=__doc__.splitlines()[0]
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser(
        "scan", help="scan the estate and summarise the credential graph"
    )
    scan.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="directory to search for scannable files (repeatable)",
    )
    scan.add_argument(
        "--crontab",
        action="append",
        default=[],
        metavar="PATH",
        help="crontab file to scan (repeatable)",
    )
    scan.add_argument(
        "--plist",
        action="append",
        default=[],
        metavar="PATH",
        help="launchd plist to scan (repeatable)",
    )
    scan.add_argument(
        "--env-file",
        action="append",
        default=[],
        metavar="PATH",
        help="env file to scan (repeatable)",
    )
    scan.add_argument(
        "--pepper-file",
        default=str(DEFAULT_PEPPER_PATH),
        metavar="PATH",
        help="machine-local pepper (created on first use, mode 0600)",
    )
    scan.add_argument(
        "--store",
        metavar="PATH",
        help="persist the credential graph to this SQLite store",
    )
    scan.add_argument("--json", action="store_true", help="emit the report as JSON")

    canary = subparsers.add_parser(
        "canary",
        help="probe one credential and record an alive/dead/unobservable verdict",
    )
    canary.add_argument("fingerprint_prefix", metavar="FINGERPRINT-PREFIX")
    canary.add_argument(
        "--provider",
        required=True,
        choices=sorted(PROVIDERS),
        help="which provider spec to probe with",
    )
    value_group = canary.add_mutually_exclusive_group(required=True)
    value_group.add_argument(
        "--value-env",
        metavar="VARNAME",
        help="env var holding the raw credential value (never argv)",
    )
    value_group.add_argument(
        "--value-file",
        metavar="PATH",
        help="file holding the raw credential value (never argv)",
    )
    canary.add_argument(
        "--store",
        required=True,
        metavar="PATH",
        help="graph store to look up the credential in and record evidence into",
    )
    canary.add_argument(
        "--pepper-file",
        default=str(DEFAULT_PEPPER_PATH),
        metavar="PATH",
        help="machine-local pepper (created on first use, mode 0600)",
    )
    canary.add_argument(
        "--url",
        metavar="URL",
        help="target URL (generic-bearer) or base URL (ntfy-write)",
    )
    canary.add_argument(
        "--header",
        default="Authorization",
        metavar="NAME",
        help="header name for the generic-bearer probe",
    )
    canary.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS")
    canary.add_argument("--json", action="store_true", help="emit the outcome as JSON")

    add_sweep_subparser(subparsers)

    return parser


def _alarm(report) -> tuple[str, int] | None:
    """Distinguish the two ways a scan can be empty without being clean."""
    if report.surface_count == 0:
        return NO_SURFACES_ALARM, EXIT_NO_SURFACES
    if report.readable_count == 0:
        return NOTHING_READABLE_ALARM, EXIT_NOTHING_READABLE
    return None


def run_scan(args) -> int:
    pepper = load_or_create_pepper(Path(args.pepper_file))
    targets, discovery_skips = resolve_targets(args)
    report = scan_estate(pepper, discovery_skips=discovery_skips, **targets)

    # Print BEFORE persisting: the scan has already done the expensive work,
    # and losing the report to an unwritable --store path is the worst trade
    # available. A persist failure is its own exit code, not a traceback.
    print(render_json(report) if args.json else render_text(report))

    alarm = _alarm(report)
    if alarm is not None:
        print(alarm[0], file=sys.stderr)

    store_failed = False
    if args.store:
        try:
            persist(report, args.store)
        except (OSError, sqlite3.Error) as exc:
            print(f"ERROR: could not write the graph store: {exc}", file=sys.stderr)
            store_failed = True

    # An alarm outranks a store failure when both fire: "the scanner saw
    # nothing" is a worse condition than "it saw something it could not
    # save", and only one exit code is available. Both are on stderr either way.
    if alarm is not None:
        return alarm[1]
    return EXIT_STORE_FAILED if store_failed else EXIT_OK


def _read_canary_value(args) -> tuple[str | None, str | None]:
    """Returns (value, error). The raw value never comes from argv."""
    if args.value_env:
        value = os.environ.get(args.value_env)
        if value is None:
            return None, f"env var {args.value_env} is not set"
        return value, None
    try:
        return Path(args.value_file).read_text().strip(), None
    except OSError as exc:
        return None, f"could not read --value-file: {exc}"


def _canary_config(args) -> dict:
    config = {}
    if args.url:
        config["url"] = args.url
        config["base_url"] = args.url
    if args.header:
        config["header"] = args.header
    return config


def run_canary(args) -> int:
    pepper = load_or_create_pepper(Path(args.pepper_file))
    value, error = _read_canary_value(args)
    if error is not None:
        print(f"ERROR: {error}", file=sys.stderr)
        return EXIT_CANARY_VALUE_UNREADABLE

    store = GraphStore(Path(args.store))
    try:
        matches = store.find_by_prefix(args.fingerprint_prefix)
        if not matches:
            print(
                f"ERROR: no credential found matching prefix {args.fingerprint_prefix!r}",
                file=sys.stderr,
            )
            return EXIT_CANARY_NOT_FOUND
        if len(matches) > 1:
            print(
                f"ERROR: ambiguous prefix {args.fingerprint_prefix!r} matches "
                f"{len(matches)} credentials -- use more characters",
                file=sys.stderr,
            )
            return EXIT_CANARY_AMBIGUOUS

        record = matches[0]
        if fingerprint(pepper, value) != record["fingerprint"]:
            print(
                "ERROR: supplied value does not match the credential on record",
                file=sys.stderr,
            )
            return EXIT_CANARY_MISMATCH

        spec = get_provider(args.provider)
        try:
            outcome = run_probe(
                spec, value, config=_canary_config(args), timeout=args.timeout
            )
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return EXIT_CANARY_BAD_CONFIG

        ts = datetime.now(timezone.utc).isoformat()
        store.record_canary_evidence(
            record["fingerprint"],
            ts,
            outcome.verdict.value,
            outcome.latency_ms,
            outcome.http_class,
        )
        if outcome.verdict is Verdict.ALIVE:
            store.update_last_verified(record["fingerprint"], ts)
    finally:
        store.close()

    renderer = render_canary_json if args.json else render_canary_text
    print(renderer(record["fingerprint"], args.provider, outcome, ts))
    return _CANARY_EXIT_BY_VERDICT[outcome.verdict]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "canary":
        return run_canary(args)
    if args.command == "sweep":
        return run_sweep_command(args)
    return run_scan(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
