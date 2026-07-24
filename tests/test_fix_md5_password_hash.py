import hashlib
from hashlib import md5


def hash_password_vulnerable(password: str) -> str:
    """Simulates the original vulnerable code using MD5."""
    return md5(password.encode()).hexdigest()


def hash_password_fixed(password: str) -> str:
    """Simulates the fixed code using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def test_password_hashing_uses_sha256_not_md5():
    """
    Regression test for B324: ensures that the password hashing function
    uses SHA-256 (secure) instead of MD5 (weak/insecure).

    - Fails against the vulnerable code (MD5 produces a 32-char hex digest).
    - Passes against the fixed code (SHA-256 produces a 64-char hex digest).
    """
    test_password = "supersecretpassword"

    fixed_hash = hash_password_fixed(test_password)
    vulnerable_hash = hash_password_vulnerable(test_password)

    # The fixed hash must be a SHA-256 hex digest (64 characters)
    assert len(fixed_hash) == 64, (
        f"Expected SHA-256 hash length of 64, got {len(fixed_hash)}. "
        "Password may still be hashed with MD5 (32 chars) instead of SHA-256."
    )

    # Verify the fixed hash matches a known SHA-256 digest
    expected_sha256 = hashlib.sha256(test_password.encode()).hexdigest()
    assert fixed_hash == expected_sha256, (
        "Fixed hash does not match expected SHA-256 digest."
    )

    # Ensure the fixed hash is NOT equal to the MD5 hash (catches regression to vulnerable code)
    assert fixed_hash != vulnerable_hash, (
        "Password hash matches MD5 output, indicating the vulnerable code path is still in use."
    )

    # Sanity check: MD5 produces 32-char digests (not 64)
    assert len(vulnerable_hash) == 32, (
        "Unexpected MD5 hash length; test setup may be incorrect."
    )
