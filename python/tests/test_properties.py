"""Property-based tests for IdentityKit. Run: python3 tests/test_properties.py
(requires hypothesis)."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hypothesis import given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from identitykit import (  # noqa: E402
    build_identity,
    did_key_from_public,
    generate_keypair,
    public_from_did_key,
    sign_identity,
    verify_identity,
)
from identitykit import signing  # noqa: E402

printable = st.text(alphabet=st.characters(min_codepoint=32, max_codepoint=126), min_size=1, max_size=24)


@settings(max_examples=200)
@given(st.binary(min_size=32, max_size=32))
def test_did_key_roundtrip(seed):
    pub = signing.public_from_seed(seed)
    assert public_from_did_key(did_key_from_public(pub)) == pub


@settings(max_examples=150)
@given(printable, st.sampled_from(["org", "person"]), st.lists(printable, max_size=4))
def test_sign_verify_roundtrips(name, otype, caps):
    seed, pub = generate_keypair()
    did = did_key_from_public(pub)
    doc = build_identity(
        did,
        {"name": name, "type": otype},
        [{"id": f"{did}#0", "purpose": ["controller"], "public_key": signing.b64(pub)}],
        capabilities=caps,
    )
    signed = sign_identity(doc, seed)
    assert verify_identity(signed) is True


@settings(max_examples=150)
@given(printable)
def test_any_tamper_breaks_verification(new_name):
    seed, pub = generate_keypair()
    did = did_key_from_public(pub)
    doc = build_identity(did, {"name": "original", "type": "org"},
                         [{"id": f"{did}#0", "purpose": ["controller"], "public_key": signing.b64(pub)}])
    signed = sign_identity(doc, seed)
    if new_name == "original":
        return  # not a tamper
    signed["operator"]["name"] = new_name
    assert verify_identity(signed) is False


@settings(max_examples=100)
@given(st.binary(min_size=32, max_size=32), st.binary(min_size=32, max_size=32))
def test_wrong_key_never_verifies_did_key(seed_a, seed_b):
    if seed_a == seed_b:
        return
    pub_a = signing.public_from_seed(seed_a)
    did = did_key_from_public(pub_a)  # id is key A
    doc = build_identity(did, {"name": "x", "type": "org"},
                         [{"id": f"{did}#0", "purpose": ["controller"], "public_key": signing.b64(pub_a)}])
    signed = sign_identity(doc, seed_b)  # signed by key B
    assert verify_identity(signed) is False


if __name__ == "__main__":
    test_did_key_roundtrip()
    test_sign_verify_roundtrips()
    test_any_tamper_breaks_verification()
    test_wrong_key_never_verifies_did_key()
    print("property tests ok")
