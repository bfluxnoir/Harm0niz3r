"""Tests for commands/android/logcat_leak_scan.py."""

from commands.android.logcat_leak_scan import _scan_text, _luhn_valid


# ---------------------------------------------------------------------------
# Luhn validator
# ---------------------------------------------------------------------------

def test_luhn_accepts_well_known_test_cards():
    assert _luhn_valid("4111111111111111")  # VISA test
    assert _luhn_valid("5500000000000004")  # MasterCard test
    assert _luhn_valid("340000000000009")   # AmEx test (15 digits)


def test_luhn_rejects_obvious_garbage():
    assert not _luhn_valid("4111111111111112")  # last digit off
    assert not _luhn_valid("1234567890123456")  # not Luhn-valid
    assert not _luhn_valid("0000")               # too short


# ---------------------------------------------------------------------------
# Pattern set
# ---------------------------------------------------------------------------

def _ids(findings):
    return {f.rule for f in findings}


def test_email_address_flagged():
    findings = _scan_text("I 09:00:00 user signed in as alice@example.com today")
    assert "EMAIL_ADDRESS" in _ids(findings)


def test_ipv4_address_flagged():
    findings = _scan_text("D 09:00 connecting to 192.168.1.42:8080")
    assert "IPV4_ADDRESS" in _ids(findings)


def test_jwt_flagged():
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    findings = _scan_text(f"I auth: token={jwt}")
    rules = _ids(findings)
    assert "JWT" in rules
    # The same value should also trigger AUTH_KEY_ASSIGN via 'token=...'.
    assert "AUTH_KEY_ASSIGN" in rules


def test_bearer_token_flagged():
    findings = _scan_text(
        'I OkHttp: --> GET /api/me  Authorization: Bearer AbCdEf0123456789AbCdEf'
    )
    assert "BEARER_TOKEN" in _ids(findings)


def test_iban_flagged():
    findings = _scan_text("I user iban: DE89370400440532013000")
    assert "IBAN" in _ids(findings)


def test_aws_and_google_keys_flagged():
    findings = _scan_text(
        "D config: aws=AKIAIOSFODNN7EXAMPLE google=AIzaSyA-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    )
    rules = _ids(findings)
    assert "AWS_ACCESS_KEY_ID" in rules
    assert "GOOGLE_API_KEY" in rules


def test_password_assignment_flagged():
    findings = _scan_text("D login(password=hunter2_long_enough)")
    assert "AUTH_KEY_ASSIGN" in _ids(findings)


def test_pan_card_with_valid_luhn_is_flagged_and_masked():
    findings = _scan_text("I checkout: cardNumber=4111 1111 1111 1111 exp=12/30")
    pan = [f for f in findings if f.rule == "PAN_CARD"]
    assert pan and pan[0].severity == "HIGH"
    # Result should be masked, never reveal the full PAN.
    masked = pan[0].match
    assert "4111" in masked and masked.count("*") >= 4
    assert "1111111111111111" not in masked


def test_pan_with_invalid_luhn_is_not_flagged():
    findings = _scan_text("I bogus: number=1234567812345678")
    assert "PAN_CARD" not in _ids(findings)


def test_clean_log_produces_no_findings():
    text = "\n".join([
        "I MainActivity: onCreate",
        "D MyApp: cache-hit for /v1/products/42",
        "W Network: retrying connection",
    ])
    assert _scan_text(text) == []
