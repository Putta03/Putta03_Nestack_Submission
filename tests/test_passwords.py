from app import security


def test_hash_and_verify_round_trip():
    encoded = security.hash_password("a long enough password", n=2**14, r=8, p=1)
    assert encoded.startswith("scrypt$")
    assert security.verify_password("a long enough password", encoded)
    assert not security.verify_password("a different password", encoded)


def test_hashes_use_unique_salts():
    first = security.hash_password("same password", n=2**14, r=8, p=1)
    second = security.hash_password("same password", n=2**14, r=8, p=1)
    assert first != second


def test_pepper_is_required_to_verify():
    pepper = b"pepper-that-lives-outside-the-database"
    encoded = security.hash_password("a long enough password", n=2**14, r=8, p=1, pepper=pepper)
    assert security.verify_password("a long enough password", encoded, pepper=pepper)
    assert not security.verify_password("a long enough password", encoded)
    assert not security.verify_password("a long enough password", encoded, pepper=b"different-pepper")


def test_tampered_hashes_are_rejected():
    encoded = security.hash_password("a long enough password", n=2**14, r=8, p=1)
    parts = encoded.split("$")
    digest = parts[-1]
    parts[-1] = digest[:10] + ("A" if digest[10] != "A" else "B") + digest[11:]
    assert not security.verify_password("a long enough password", "$".join(parts))


def test_malformed_hashes_are_rejected():
    for encoded in ("", "plaintext", "bcrypt$1$2$3$4$5", "scrypt$x$8$1$AA$BB"):
        assert not security.verify_password("anything", encoded)


def test_session_tokens_are_random_and_hashable():
    first = security.new_session_token()
    second = security.new_session_token()
    assert len(first) == 43
    assert first != second
    assert security.hash_session_token(first) != first
    assert len(security.hash_session_token(first)) == 64
    assert security.hash_session_token("too-short") is None
