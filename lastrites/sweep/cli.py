"""The `lastrites sweep` argparse wiring and command handler.

Kept out of `lastrites/cli.py` so that file stays under its architecture
limits -- this module owns everything sweep-specific: the subparser, and
the try/except boundary that makes the heartbeat write capture-based (see
`sweep.run_sweep`'s docstring for why the whole body has to live inside
one try).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from lastrites.core.pepper import DEFAULT_PEPPER_PATH, load_or_create_pepper
from lastrites.scan.discovery import resolve_targets
from lastrites.sweep.channel import load_channel_config
from lastrites.sweep.contract import invoked_by as sweep_invoked_by
from lastrites.sweep.escalation import EscalationConfig
from lastrites.sweep.heartbeat import DEFAULT_HEARTBEAT_PATH, read_heartbeat
from lastrites.sweep.registry import load_registrations
from lastrites.sweep.report import render_json as render_sweep_json
from lastrites.sweep.report import render_text as render_sweep_text
from lastrites.sweep.sweep import run_sweep

EXIT_SWEEP_OK = 0
EXIT_SWEEP_FAILED = 1


def add_sweep_subparser(subparsers) -> None:
    sweep = subparsers.add_parser(
        "sweep",
        help="scan the estate, canary registered credentials, and evaluate escalation rules",
    )
    sweep.add_argument(
        "--root",
        action="append",
        default=[],
        metavar="DIR",
        help="directory to search for scannable files (repeatable)",
    )
    sweep.add_argument(
        "--crontab",
        action="append",
        default=[],
        metavar="PATH",
        help="crontab file to scan (repeatable)",
    )
    sweep.add_argument(
        "--plist",
        action="append",
        default=[],
        metavar="PATH",
        help="launchd plist to scan (repeatable)",
    )
    sweep.add_argument(
        "--env-file",
        action="append",
        default=[],
        metavar="PATH",
        help="env file to scan (repeatable)",
    )
    sweep.add_argument(
        "--pepper-file",
        default=str(DEFAULT_PEPPER_PATH),
        metavar="PATH",
        help="machine-local pepper (created on first use, mode 0600)",
    )
    sweep.add_argument(
        "--store",
        required=True,
        metavar="PATH",
        help="graph store to scan into, canary against, and evaluate escalation from",
    )
    sweep.add_argument(
        "--credentials-config",
        metavar="PATH",
        help="JSON list of {fingerprint_prefix, provider, value_env|value_file, config} "
        "entries to canary this sweep (default: none registered)",
    )
    sweep.add_argument(
        "--alert-channel-config",
        metavar="PATH",
        help="JSON {command: [...]} channel config, with {message} substituted into each "
        "argument (default: alerts are computed but not sent)",
    )
    sweep.add_argument(
        "--lead-time-days",
        type=float,
        default=7.0,
        metavar="DAYS",
        help="page this many days before a credential's known expiry",
    )
    sweep.add_argument(
        "--unobservable-threshold",
        type=int,
        default=3,
        metavar="N",
        help="page after this many consecutive UNOBSERVABLE canary results",
    )
    sweep.add_argument(
        "--heartbeat-file",
        default=str(DEFAULT_HEARTBEAT_PATH),
        metavar="PATH",
        help="capture-based heartbeat, written only on a fully completed sweep",
    )
    sweep.add_argument("--timeout", type=float, default=5.0, metavar="SECONDS")
    sweep.add_argument("--json", action="store_true", help="emit the report as JSON")


def run_sweep_command(args) -> int:
    # Everything, including config loading, lives inside the try: a bad
    # --credentials-config/--alert-channel-config path is exactly as much
    # a mid-sweep failure as a canary or escalation crash, and must leave
    # no heartbeat behind the same way.
    try:
        pepper = load_or_create_pepper(Path(args.pepper_file))
        targets, discovery_skips = resolve_targets(args)
        registrations = (
            load_registrations(Path(args.credentials_config))
            if args.credentials_config
            else []
        )
        channel_config = (
            load_channel_config(Path(args.alert_channel_config))
            if args.alert_channel_config
            else None
        )
        escalation_config = EscalationConfig(
            lead_time_days=args.lead_time_days,
            unobservable_threshold=args.unobservable_threshold,
        )
        report = run_sweep(
            pepper=pepper,
            store_path=args.store,
            targets=targets,
            discovery_skips=discovery_skips,
            registrations=registrations,
            escalation_config=escalation_config,
            channel_config=channel_config,
            invoked_by=sweep_invoked_by(),
            heartbeat_path=args.heartbeat_file,
            now=datetime.now(timezone.utc),
            timeout=args.timeout,
        )
    except Exception as exc:  # noqa: BLE001 -- capture-based: no heartbeat on any failure, by design
        print(
            f"ERROR: sweep failed before completion -- no heartbeat written: {exc}",
            file=sys.stderr,
        )
        return EXIT_SWEEP_FAILED

    heartbeat = read_heartbeat(args.heartbeat_file)
    renderer = render_sweep_json if args.json else render_sweep_text
    print(renderer(heartbeat, report))
    return EXIT_SWEEP_OK
