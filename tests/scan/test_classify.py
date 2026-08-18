"""Classification: read the evidence, or say `unknown`. Never guess.

A wrong provider label sends the operator to the wrong dashboard during an
outage, which is worse than no label at all.
"""

import pytest

from lastrites.scan.classify import UNKNOWN, classify


def test_key_name_is_its_own_documentation():
    result = classify(
        "CLOUDFLARE_API_TOKEN", "mock-cf-7f3a2b91c4d6e805a1b2c3d4e5f60718"
    )
    assert result.provider == "cloudflare"
    assert result.kind == "api-token"


@pytest.mark.parametrize(
    "key,expected",
    [
        ("AWS_SECRET_ACCESS_KEY", "aws"),
        ("GITHUB_TOKEN", "github"),
        ("STRIPE_SECRET_KEY", "stripe"),
        ("SLACK_BOT_TOKEN", "slack"),
        ("OPENAI_API_KEY", "openai"),
        ("ANTHROPIC_API_KEY", "anthropic"),
    ],
)
def test_provider_from_key_name(key, expected):
    assert classify(key, "mock-2f8b4d16a09c7e35").provider == expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("AKIAmock-4TZQ7XN2PLWD6VBK", "aws"),
        ("ghp_mock-3f9a2b7c1d5e8a4f6b0c", "github"),
        ("sk_live_mock-9d1c4e7a2b60f835", "stripe"),
        ("xoxb-mock-5518-2290-a7f31c9e4b", "slack"),
        ("sk-ant-mock-6c2e9a4f1b78d035", "anthropic"),
    ],
)
def test_provider_from_value_shape_when_the_key_says_nothing(value, expected):
    assert classify("TOKEN_A", value).provider == expected


def test_unmatchable_value_is_unknown_and_never_guessed():
    result = classify("WIDGET_BLOB", "mock-8f4a1c6e9b2d7503aefb1c8d4620937e")
    assert result.provider == UNKNOWN
    assert result.kind == UNKNOWN


def test_kind_is_read_from_the_key_name():
    assert classify("DATABASE_PASSWORD", "mock-pw-9c2e5a81f7b04d63").kind == "password"
    assert (
        classify("AWS_ACCESS_KEY_ID", "AKIAmock-4TZQ7XN2PLWD").kind == "access-key-id"
    )


def test_a_webhook_secret_is_a_signing_secret_not_an_endpoint():
    """The thing that signs the payload is not the URL it is posted to."""
    assert classify("BACKUP_WEBHOOK_SECRET", "mock-wh-1a9c4e77b2d05f6381ea").kind == (
        "signing-secret"
    )
    assert classify(
        "SLACK_WEBHOOK_URL", "https://mock.invalid/hooks/mock-9c2e"
    ).kind == ("webhook-url")


def test_pem_body_classifies_as_a_private_key_by_shape():
    # armor assembled at runtime so the literal never sits in a tracked file
    # (the on-disk secret scanner refuses PEM armor even in a test)
    mark = "-----BEGIN RSA " + "PRIVATE KEY-----"
    end = "-----END RSA " + "PRIVATE KEY-----"
    pem = f"{mark}\nmock-pk-3a91c5\n{end}"
    assert classify("BLOB", pem).kind == "private-key"


def test_json_service_account_classifies_by_shape():
    blob = '{"type": "service_account", "private_key": "mock-pk-8a3f2c9d1b"}'
    result = classify("BLOB", blob)
    assert result.kind == "service-account-json"
    assert result.provider == "google"


def test_key_name_evidence_outranks_value_shape():
    """An explicitly named key is stronger evidence than a prefix guess."""
    result = classify("CLOUDFLARE_API_TOKEN", "ghp_mock-3f9a2b7c1d5e8a4f6b0c")
    assert result.provider == "cloudflare"


def test_rotation_class_is_unknown_until_a_provider_registry_says_otherwise():
    """LR1.3 owns the provider registry; LR1.2 must not invent rotation claims."""
    assert classify("WIDGET_BLOB", "mock-8f4a1c6e9b2d").rotation_class == UNKNOWN
