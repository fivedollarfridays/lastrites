"""Loading the sweep's credential registrations from operator-owned config."""

from __future__ import annotations

import json

from lastrites.sweep.registry import CredentialRegistration, load_registrations


def test_load_registrations_parses_a_json_list(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            [
                {
                    "fingerprint_prefix": "3f9a2b7c",
                    "provider": "cloudflare",
                    "value_env": "CF_TOKEN",
                },
                {
                    "fingerprint_prefix": "aa11bb22",
                    "provider": "github",
                    "value_file": "/run/secrets/gh",
                },
            ]
        )
    )
    registrations = load_registrations(path)
    assert registrations == [
        CredentialRegistration(
            fingerprint_prefix="3f9a2b7c", provider="cloudflare", value_env="CF_TOKEN"
        ),
        CredentialRegistration(
            fingerprint_prefix="aa11bb22",
            provider="github",
            value_file="/run/secrets/gh",
        ),
    ]


def test_defaults_when_optional_fields_are_absent(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps([{"fingerprint_prefix": "deadbeef", "provider": "generic-bearer"}])
    )
    [registration] = load_registrations(path)
    assert registration.value_env is None
    assert registration.value_file is None
    assert registration.config == {}


def test_per_registration_provider_config_is_preserved(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            [
                {
                    "fingerprint_prefix": "deadbeef",
                    "provider": "generic-bearer",
                    "value_env": "X",
                    "config": {"url": "https://example.internal/health"},
                }
            ]
        )
    )
    [registration] = load_registrations(path)
    assert registration.config == {"url": "https://example.internal/health"}


def test_empty_list_is_valid(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text("[]")
    assert load_registrations(path) == []
