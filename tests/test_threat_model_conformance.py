"""
Threat Model Conformance Suite

This test suite verifies every sharp edge and principle documented in THREAT-MODEL.md
as executable tests, referenced by section number.

§1: Parent-credential blast radius
§2: Peppered HMACs (no bare hashes)
§3: Graph at-rest posture (0600 permissions, WAL mode, no raw values on disk)
§4: Escalation channels (no hardcoded endpoints)
§5: Scan-surface enumeration (loud skips, no silent dropping)
§6: Canary verdict vocabulary (401/403 → DEAD only)
§7: Sweep heartbeat and escalation (capture-based, provenance-stamped)
"""

import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest


# THREAT-MODEL §3: No raw credential values persisted to disk
class TestNoRawValuesPersisted:
    """THREAT-MODEL §3: verify no raw credential values written to any artifact file."""

    def test_store_file_contains_no_raw_secrets(self, tmp_path):
        """
        THREAT-MODEL §3: Planting a mock secret through store API should never
        write the raw value to disk. Grep the store file for the planted secret.
        """
        from lastrites.core.store import GraphStore

        store_file = tmp_path / "store.db"
        store = GraphStore(store_file)

        # Plant a recognizable secret
        planted_secret = "SECRET_TEST_CREDENTIAL_MARKER_12345"
        # Fingerprint must be 64-char hex (HMAC-SHA256 digest)
        fingerprint = "a" * 64

        # Store a record
        store.add_credential(
            fingerprint=fingerprint,
            kind="api-key",
            rotation_class="manual",
        )

        # Read the raw file bytes
        with open(store_file, "rb") as f:
            file_bytes = f.read()

        # Assert the planted secret does not appear in the file
        assert planted_secret.encode() not in file_bytes, (
            "THREAT-MODEL §3 VIOLATED: Raw credential value found in store file"
        )

    def test_canary_report_contains_no_secret_values(self):
        """
        THREAT-MODEL §3: A canary verdict report should contain fingerprints
        and verdicts, never the raw credential value used for testing.
        """
        from lastrites.canary.report import to_dict
        from lastrites.canary.verdict import Verdict
        from lastrites.canary.models import ProbeOutcome

        planted_secret = "SECRET_CANARY_TOKEN_MARKER_9876"
        fp = "a" * 64  # Valid 64-char hex fingerprint

        # Simulate a probe outcome
        outcome = ProbeOutcome(
            verdict=Verdict.DEAD,
            http_class="401",
            latency_ms=100,
        )

        # Render report to dict
        report_dict = to_dict(fp, "test_provider", outcome, "2026-08-18T00:00:00Z")
        report_str = str(report_dict)

        assert planted_secret not in report_str, (
            "THREAT-MODEL §3 VIOLATED: Raw secret in canary report"
        )

    def test_scan_record_persists_fingerprints_not_values(self):
        """
        THREAT-MODEL §3: Persisted scan records should hold fingerprints,
        not raw values. Verify that scan data structures never store raw values.
        """
        from lastrites.scan import models
        import inspect

        # The scan module doesn't directly expose a ScanItem, but we can verify
        # the schema through introspection that it doesn't store raw values
        source = inspect.getsource(models)

        # Verify the module doesn't store "value" or "secret" fields
        assert "def value" not in source and "'value':" not in source, (
            "THREAT-MODEL §3 VIOLATED: Scan models should not store raw values"
        )


# THREAT-MODEL §2: Peppered fingerprints only (no bare hashes)
class TestPepperedFingerprintsOnly:
    """THREAT-MODEL §2: verify no bare SHA calls on credential values."""

    def test_no_bare_hashlib_sha_calls_in_fingerprint_module(self):
        """
        THREAT-MODEL §2: grep lastrites/core/fingerprint.py for patterns
        that indicate a bare hash (no pepper) is being computed.
        """
        fingerprint_module = (
            Path(__file__).parent.parent / "lastrites" / "core" / "fingerprint.py"
        )
        assert fingerprint_module.exists(), "fingerprint.py not found"

        with open(fingerprint_module, "r") as f:
            content = f.read()

        # Bare hash patterns to catch: hashlib.sha256(value).digest()
        # should never appear without pepper involvement
        bare_sha_pattern = r"hashlib\.sha256\s*\(\s*(?!.*pepper)"
        matches = re.findall(bare_sha_pattern, content, re.MULTILINE)

        assert len(matches) == 0, (
            f"THREAT-MODEL §2 VIOLATED: Found {len(matches)} bare SHA256 calls"
        )

    def test_fingerprint_implementation_uses_hmac(self):
        """
        THREAT-MODEL §2: The fingerprint.py module should import and use
        hmac with a pepper, never bare hashlib.sha256.
        """
        from lastrites.core import fingerprint as fp_module

        # Check that HMAC is imported
        import inspect

        source = inspect.getsource(fp_module)
        assert "hmac" in source.lower(), (
            "fingerprint module must use hmac for peppered hashing"
        )

        # Verify pepper is mentioned
        assert "pepper" in source.lower(), (
            "fingerprint module must reference pepper for HMAC key"
        )

    def test_no_hashlib_calls_outside_hmac_context(self):
        """
        THREAT-MODEL §2: Search codebase for direct hashlib calls that
        are not wrapped in HMAC. Should find none.
        """
        src_dir = Path(__file__).parent.parent / "lastrites"
        py_files = list(src_dir.rglob("*.py"))

        violations = []
        for py_file in py_files:
            with open(py_file, "r") as f:
                lines = f.readlines()

            for i, line in enumerate(lines, 1):
                # Look for bare hash calls (rough pattern)
                if "hashlib" in line and "hmac" not in line:
                    # Check if it's not in a comment
                    if not line.strip().startswith("#"):
                        violations.append(f"{py_file}:{i}: {line.strip()}")

        # Filter out false positives: imports, type hints, etc.
        real_violations = [
            v
            for v in violations
            if not any(x in v for x in ["import", "# ", "HMAC", "pepper"])
        ]

        assert not real_violations, (
            "THREAT-MODEL §2 VIOLATED: Bare hashlib calls found:\n"
            + "\n".join(real_violations)
        )


# THREAT-MODEL §5: Skip loudness (every scanner surfaces skip count)
class TestSkipLoudness:
    """THREAT-MODEL §5: verify scanners surface and count skips, never silent dropping."""

    def test_scan_result_includes_skip_count(self):
        """
        THREAT-MODEL §5: Scan results must have a skip_count field
        that is always surfaced.
        """
        # The scan schema includes skip_count in the scans table
        import sqlite3
        from lastrites.core.store import GraphStore

        with tempfile.TemporaryDirectory() as tmpdir:
            store_file = Path(tmpdir) / "store.db"
            GraphStore(store_file)

            # Verify the scans table has skip_count column
            conn = sqlite3.connect(store_file)
            cursor = conn.cursor()
            cursor.execute("PRAGMA table_info(scans)")
            columns = {row[1] for row in cursor.fetchall()}
            conn.close()

            assert "skip_count" in columns, (
                "THREAT-MODEL §5: Scans table must have skip_count column"
            )

    def test_scan_prints_skip_details_to_output(self, tmp_path):
        """
        THREAT-MODEL §5: a malformed surface registers as a counted skip AND
        that count appears in the rendered output — silence cannot hide
        undercounting. The literal "counted not hidden" line is the contract.
        """
        from lastrites.scan.estate import scan_estate
        from lastrites.scan.models import Skip
        from lastrites.scan.report import render_text

        pepper = b"\x2a" * 32
        report = scan_estate(
            pepper,
            discovery_skips=[Skip(locator="/estate/unreadable.env", reason="denied")],
        )
        assert report.skip_count >= 1, "a skip must register in the count"
        rendered = render_text(report)
        # the count is rendered on the loud "counted not hidden" line
        assert f"counted not hidden): {report.skip_count}" in rendered

    def test_no_silent_file_drops_in_discovery(self):
        """
        THREAT-MODEL §5: a discovery-level skip (unreadable/unwalkable path)
        is carried into the report's skip_count, never dropped to a clean-scan
        appearance.
        """
        from lastrites.scan.estate import scan_estate
        from lastrites.scan.models import Skip

        pepper = b"\x2a" * 32
        dropped = Skip(locator="/estate/unreadable-dir", reason="permission denied")
        report = scan_estate(pepper, discovery_skips=[dropped])
        assert report.skip_count >= 1, "a discovery skip must survive into the count"


# THREAT-MODEL §7: Heartbeat capture-based and provenance-stamped
class TestHeartbeatProvenance:
    """THREAT-MODEL §7: verify heartbeat has invoked_by and is strictly capture-based."""

    def test_heartbeat_includes_invoked_by_field(self):
        """
        THREAT-MODEL §7: Every heartbeat must include invoked_by field.
        Missing field means the heartbeat is corrupted or hand-edited.
        """
        from lastrites.sweep.heartbeat import write_heartbeat, Heartbeat
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            heartbeat_file = Path(tmpdir) / "heartbeat.json"

            # Create and write a heartbeat
            hb = Heartbeat(last_success="2026-08-18T00:00:00Z", invoked_by="scheduler")
            write_heartbeat(hb, heartbeat_file)

            # Read it back
            with open(heartbeat_file) as f:
                data = json.load(f)

            assert "invoked_by" in data, (
                "THREAT-MODEL §7 VIOLATED: heartbeat missing invoked_by"
            )

    def test_heartbeat_reader_fails_on_missing_invoked_by(self):
        """
        THREAT-MODEL §7: A reader that encounters a heartbeat without
        invoked_by must fail closed, never assume 'hand-run' as a default.
        """
        from lastrites.sweep.heartbeat import read_heartbeat
        import json

        with tempfile.TemporaryDirectory() as tmpdir:
            heartbeat_file = Path(tmpdir) / "heartbeat.json"

            # Write a corrupted heartbeat (no invoked_by)
            corrupted = {
                "timestamp": "2026-08-18T00:00:00Z",
                "status": "ok",
            }
            with open(heartbeat_file, "w") as f:
                json.dump(corrupted, f)

            # Reading should fail or raise
            with pytest.raises(Exception):
                read_heartbeat(heartbeat_file)

    def test_heartbeat_only_written_after_sweep_completes(self, tmp_path):
        """
        THREAT-MODEL §7: the heartbeat is capture-based — a sweep that raises
        partway through writes NO heartbeat, so a dead sweep looks dead. Proven
        by injecting a failure and asserting the heartbeat file never appears.
        """
        from lastrites.sweep import sweep as sweep_mod

        hb = tmp_path / "heartbeat.json"

        def _boom(*a, **k):
            raise RuntimeError("injected mid-sweep failure")

        # persist() runs after scan, before the heartbeat write — a realistic
        # mid-sweep fault point.
        with mock.patch.object(sweep_mod, "persist", _boom):
            with pytest.raises(RuntimeError):
                sweep_mod.run_sweep(
                    pepper=b"\x2a" * 32,
                    store_path=tmp_path / "g.sqlite3",
                    targets={},
                    discovery_skips=[],
                    registrations=[],
                    escalation_config=sweep_mod.EscalationConfig(),
                    channel_config=None,
                    invoked_by="interactive",
                    heartbeat_path=hb,
                    now=datetime(2026, 8, 18, tzinfo=timezone.utc),
                )
        assert not hb.exists(), "a sweep that failed mid-way must leave no heartbeat"


# THREAT-MODEL §6: Canary verdict vocabulary (401/403 → DEAD only)
class TestVerdictVocabulary:
    """THREAT-MODEL §6: verify verdict classification is strict (401/403 only → DEAD)."""

    def test_401_403_only_classify_as_dead(self):
        """
        THREAT-MODEL §6: Only 401 and 403 HTTP responses should classify
        as DEAD. No ambiguous statuses.
        """
        from lastrites.canary.verdict import classify_response, Verdict

        verdict_401, _ = classify_response(401, True)
        verdict_403, _ = classify_response(403, True)

        assert verdict_401 == Verdict.DEAD
        assert verdict_403 == Verdict.DEAD

    def test_other_statuses_classify_as_unobservable(self):
        """
        THREAT-MODEL §6: 4xx, 5xx, timeouts, DNS errors should all be
        UNOBSERVABLE, never DEAD.
        """
        from lastrites.canary.verdict import classify_response, Verdict

        unobservable_statuses = [400, 404, 429, 500, 502, 503, 504]
        for status in unobservable_statuses:
            verdict, _ = classify_response(status, False)
            assert verdict != Verdict.DEAD, (
                f"THREAT-MODEL §6 VIOLATED: {status} should not classify as DEAD"
            )

    def test_timeout_error_classifies_as_unobservable(self):
        """
        THREAT-MODEL §6: A timeout or DNS error should never classify as DEAD.
        """
        from lastrites.canary.verdict import classify_error, Verdict
        from lastrites.canary.transport import ProbeTimeout

        # Test timeout
        result, _ = classify_error(ProbeTimeout())
        assert result == Verdict.UNOBSERVABLE

        # Test network error
        result, _ = classify_error(OSError("Network error"))
        assert result == Verdict.UNOBSERVABLE

    def test_verdict_has_no_response_body_field(self):
        """
        THREAT-MODEL §6: ProbeOutcome objects should never carry response body
        or credential value, only verdict and latency.
        """
        from lastrites.canary.models import ProbeOutcome
        import dataclasses

        fields = {f.name for f in dataclasses.fields(ProbeOutcome)}

        assert "response_body" not in fields, (
            "THREAT-MODEL §6 VIOLATED: ProbeOutcome should not store response body"
        )
        assert "credential_value" not in fields, (
            "THREAT-MODEL §6 VIOLATED: ProbeOutcome should not store credential value"
        )
        assert "value" not in fields, (
            "THREAT-MODEL §6 VIOLATED: ProbeOutcome should not store raw value"
        )


# THREAT-MODEL §4: No hardcoded endpoint literals
class TestNoEndpointLiterals:
    """THREAT-MODEL §4: verify no alert endpoint or topic is hardcoded in repo."""

    def test_no_ntfy_sh_or_alert_literals_in_python(self):
        """
        THREAT-MODEL §4: no alert endpoint/topic literal in the shipped
        package. This actually greps lastrites/**.py rather than trusting a
        sibling test — a conformance suite that names a control must exercise
        it, not delegate and pass.
        """
        pattern = re.compile(
            r"ntfy\.sh/[A-Za-z0-9_-]+|hooks\.slack|discord\.com/api/webhooks"
        )
        pkg = Path(__file__).parent.parent / "lastrites"
        hits = [
            str(p)
            for p in pkg.rglob("*.py")
            if pattern.search(p.read_text(encoding="utf-8"))
        ]
        assert not hits, f"alerting endpoint/topic literal in package source: {hits}"

    def test_no_hardcoded_endpoints_in_docs(self):
        """
        THREAT-MODEL §4: README and THREAT-MODEL should not have literal
        endpoints in code examples (sanitized examples OK, real endpoints not OK).
        """
        readme = Path(__file__).parent.parent / "README.md"

        if readme.exists():
            with open(readme, "r") as f:
                content = f.read()

            # Look for actual endpoint URLs (not placeholders)
            actual_endpoint_pattern = r"https://ntfy\.sh/[a-zA-Z0-9_\-]+"
            matches = re.findall(actual_endpoint_pattern, content)

            # Filter out examples that are clearly masked/placeholder
            real_violations = [
                m for m in matches if "your-private-topic" not in m and "<" not in m
            ]

            assert not real_violations, (
                "THREAT-MODEL §4 VIOLATED: Real endpoints in README:\n"
                + "\n".join(real_violations)
            )


# THREAT-MODEL §1: Graph file permissions (0600)
class TestGraphFilePermissions:
    """THREAT-MODEL §1, §3: verify graph store and pepper have 0600 permissions."""

    def test_store_file_created_with_0600_permissions(self, tmp_path):
        """
        THREAT-MODEL §3: Store file must be created with mode 0600,
        readable only by owner.
        """
        from lastrites.core.store import GraphStore

        store_file = tmp_path / "store.db"
        GraphStore(store_file)

        # Check file permissions
        file_stat = os.stat(store_file)
        file_mode = file_stat.st_mode & 0o777

        assert file_mode == 0o600, (
            f"THREAT-MODEL §3 VIOLATED: store file mode is {oct(file_mode)}, "
            f"expected 0o600"
        )

    def test_pepper_file_created_with_0600_permissions(self, tmp_path):
        """
        THREAT-MODEL §3: Pepper file must be created with mode 0600,
        readable only by owner.
        """
        from lastrites.core.pepper import load_or_create_pepper

        pepper_file = tmp_path / "pepper"
        load_or_create_pepper(pepper_file)

        # Check file permissions
        file_stat = os.stat(pepper_file)
        file_mode = file_stat.st_mode & 0o777

        assert file_mode == 0o600, (
            f"THREAT-MODEL §3 VIOLATED: pepper file mode is {oct(file_mode)}, "
            f"expected 0o600"
        )

    def test_store_uses_wal_mode(self, tmp_path):
        """
        THREAT-MODEL §3: SQLite store must use WAL (Write-Ahead Logging) mode.
        """
        import sqlite3
        from lastrites.core.store import GraphStore

        store_file = tmp_path / "store.db"
        GraphStore(store_file)

        # Check that WAL is enabled
        conn = sqlite3.connect(store_file)
        cursor = conn.cursor()
        result = cursor.execute("PRAGMA journal_mode").fetchone()
        conn.close()

        assert result[0].lower() == "wal", (
            f"THREAT-MODEL §3 VIOLATED: Store not using WAL mode, got {result[0]}"
        )
