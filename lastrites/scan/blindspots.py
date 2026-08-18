"""The surface classes this scanner structurally cannot see.

THREAT-MODEL "secrets it cannot see" and DESIGN §Open problems 1 both say
the same thing: coverage boundaries are declared, never implied. A scan
report without this list reads as "these are all your credentials," which
is a claim lastrites is not able to make about any estate.

These are declared blind spots, not detected ones -- they are printed
whether or not anything was found, including on an empty scan.
"""

from __future__ import annotations

from lastrites.scan.models import BlindSpot

DEFAULT_BLIND_SPOTS = (
    BlindSpot(
        "os-keychain",
        "macOS Keychain / Secret Service entries: not readable without an "
        "explicit grant this scanner does not request.",
    ),
    BlindSpot(
        "compiled-binaries",
        "Values baked into compiled executables or bundled app resources.",
    ),
    BlindSpot(
        "derived-copies",
        "Base64-wrapped, URL-embedded (https://user:TOKEN@host) or KDF-derived "
        "copies: a different byte string, so they do not fingerprint-match.",
    ),
    BlindSpot(
        "runtime-injected",
        "Secrets injected at process start by another manager (vault agent, "
        "systemd credentials, CI runner env): never on disk to be read.",
    ),
    BlindSpot(
        "remote-hosts",
        "Every machine this scan did not run on. Coverage is per-machine; "
        "the estate is not.",
    ),
    BlindSpot(
        "ci-secret-stores",
        "GitHub Actions / GitLab CI / provider dashboard secret stores: "
        "API-side, not filesystem-side.",
    ),
)
