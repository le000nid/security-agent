import pytest

from app.validation import TargetValidationError, validate_target_url


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("http://localhost:3000", "http://localhost:3000"),
        ("HTTPS://127.0.0.1:8443/", "https://127.0.0.1:8443"),
        ("http://juice-shop:3000/path", "http://juice-shop:3000/path"),
    ],
)
def test_allows_only_expected_local_hosts(value: str, expected: str) -> None:
    assert validate_target_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "https://example.com",
        "http://0.0.0.0:3000",
        "http://localhost:3000/,https://example.com",
        "http://local\nhost:3000",
        "http://localhost.evil.example:3000",
        "http://localhost@evil.example:3000",
        "ftp://localhost:3000",
        "localhost:3000",
        "http://user:pass@localhost:3000",
        "http://[::1]:3000",
    ],
)
def test_rejects_non_allowlisted_or_malformed_targets(value: str) -> None:
    with pytest.raises(TargetValidationError):
        validate_target_url(value)
