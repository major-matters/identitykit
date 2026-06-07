"""IdentityKit core tests. Run: python3 tests/test_identitykit.py"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from identitykit import (  # noqa: E402
    ReputationLog,
    build_identity,
    crosswalk,
    did_key_from_public,
    generate_keypair,
    make_attestation,
    public_from_did_key,
    resolve,
    sign_identity,
    verify_attestation,
    verify_identity,
)
from identitykit.identity import validate  # noqa: E402
from identitykit.errors import InvalidIdentity, ResolutionError  # noqa: E402
from identitykit.resolver import _host_is_blocked  # noqa: E402
from identitykit import public_from_did_key  # noqa: E402
from identitykit import signing  # noqa: E402


def _did_key_identity(seed, pub, **over):
    did = did_key_from_public(pub)
    return build_identity(
        id=did,
        operator={"name": "Acme Robotics", "type": "org"},
        keys=[{"id": f"{did}#0", "purpose": ["controller", "auth", "mandate-issuer"],
               "public_key": signing.b64(pub)}],
        capabilities=["search", "purchase"],
        bindings=[{"standard": "ap2", "ref": "ap2:issuer:acme"}],
        created="2026-06-07T00:00:00Z",
        **over,
    )


def test_did_key_roundtrip():
    seed, pub = generate_keypair()
    did = did_key_from_public(pub)
    assert did.startswith("did:key:z")
    assert public_from_did_key(did) == pub


def test_sign_and_verify_did_key():
    seed, pub = generate_keypair()
    signed = sign_identity(_did_key_identity(seed, pub), seed)
    assert verify_identity(signed) is True


def test_tamper_breaks_verification():
    seed, pub = generate_keypair()
    signed = sign_identity(_did_key_identity(seed, pub), seed)
    signed["operator"]["name"] = "Evil Corp"
    assert verify_identity(signed) is False


def test_did_key_proof_must_match_id():
    # Sign a did:key identity with a DIFFERENT key than the one in the id.
    seed1, pub1 = generate_keypair()
    seed2, pub2 = generate_keypair()
    doc = _did_key_identity(seed1, pub1)  # id encodes pub1
    signed = sign_identity(doc, seed2)    # but signed by seed2 -> self-cert fails
    assert verify_identity(signed) is False


def test_validate_rejects_bad_structure():
    seed, pub = generate_keypair()
    for bad in (
        {"id": "did:key:zABC", "operator": {"name": "x", "type": "alien"}, "keys": []},
        {"id": "not-a-did", "operator": {"name": "x", "type": "org"}, "keys": [{"id": "k", "purpose": "auth", "public_key": signing.b64(pub)}]},
    ):
        try:
            validate(bad)
            assert False, "expected InvalidIdentity"
        except InvalidIdentity:
            pass


def test_resolve_did_key_offline():
    seed, pub = generate_keypair()
    did = did_key_from_public(pub)
    res = resolve(did)
    assert res["method"] == "key"
    assert signing.unb64(res["public_key"]) == pub


def test_resolve_did_web_with_injected_fetch():
    # did:web identity hosted at example.com, fetched via an injected transport.
    seed, pub = generate_keypair()
    did = "did:web:example.com"
    doc = build_identity(
        id=did,
        operator={"name": "Example Co", "type": "org"},
        keys=[{"id": f"{did}#owner", "purpose": ["controller", "auth"], "public_key": signing.b64(pub)}],
        created="2026-06-07T00:00:00Z",
    )
    signed = sign_identity(doc, seed)
    captured = {}

    def fake_fetch(url):
        captured["url"] = url
        return signed

    out = resolve(did, fetch=fake_fetch)
    assert captured["url"] == "https://example.com/.well-known/agent-identity.json"
    assert out["operator"]["name"] == "Example Co"


def test_resolve_did_web_rejects_id_mismatch():
    seed, pub = generate_keypair()
    doc = build_identity(
        id="did:web:evil.com",
        operator={"name": "x", "type": "org"},
        keys=[{"id": "k", "purpose": ["controller"], "public_key": signing.b64(pub)}],
    )
    signed = sign_identity(doc, seed)
    try:
        resolve("did:web:example.com", fetch=lambda url: signed)
        assert False, "expected InvalidIdentity on id mismatch"
    except InvalidIdentity:
        pass


def test_crosswalk_did_document():
    seed, pub = generate_keypair()
    signed = sign_identity(_did_key_identity(seed, pub), seed)
    did_doc = crosswalk.to_did_document(signed)
    assert did_doc["id"] == signed["id"]
    assert did_doc["verificationMethod"][0]["type"] == "Ed25519VerificationKey2020"
    assert "authentication" in did_doc  # the 'auth' purpose mapped through


def test_crosswalk_ap2_issuer():
    seed, pub = generate_keypair()
    signed = sign_identity(_did_key_identity(seed, pub), seed)
    ap2 = crosswalk.ap2_issuer(signed)
    assert ap2["issuer_id"] == signed["id"]
    assert ap2["operator"] == "Acme Robotics"
    assert signing.b64(pub) in ap2["mandate_issuer_keys"]
    assert ap2["ap2_binding"] == "ap2:issuer:acme"


def test_reputation_log_verifies_and_rejects():
    subj_seed, subj_pub = generate_keypair()
    iss_seed, iss_pub = generate_keypair()
    subject = did_key_from_public(subj_pub)
    issuer = did_key_from_public(iss_pub)
    att = make_attestation(subject, "mandate-honored", issuer, iss_seed,
                           evidence_ref="witnesskit:trail:abc", time="2026-06-07T00:00:00Z")
    assert verify_attestation(att) is True

    log = ReputationLog()
    log.add(att)
    assert len(log.for_subject(subject)) == 1

    # tamper -> rejected
    att["subject"] = "did:key:zEVIL"
    try:
        log.add(att)
        assert False, "expected rejection of tampered attestation"
    except ValueError:
        pass


def test_attestation_issuer_key_must_match_did_key():
    iss_seed, iss_pub = generate_keypair()
    other_seed, other_pub = generate_keypair()
    issuer = did_key_from_public(iss_pub)
    # forge: claim issuer is iss but sign with other_seed
    claim = {"subject": "did:key:zX", "type": "mandate-honored", "issuer": issuer}
    forged = {**claim, "proof": signing.make_proof(claim, other_seed)}
    assert verify_attestation(forged) is False


def test_did_web_ssrf_blocked():
    # Regression: the default resolver must refuse internal/loopback hosts.
    for bad in ("localhost", "127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "foo.local", "::1"):
        assert _host_is_blocked(bad), bad
    for ok in ("example.com", "agents.acme.io", "8.8.8.8"):
        assert not _host_is_blocked(ok), ok
    try:
        resolve("did:web:169.254.169.254")  # default fetcher -> blocked before any network
        assert False, "expected ResolutionError on metadata host"
    except ResolutionError:
        pass


def test_did_key_length_cap():
    try:
        public_from_did_key("did:key:z" + "1" * 200)
        assert False, "expected ValueError on oversized did:key"
    except ValueError:
        pass


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
    print(f"\n{len(fns)}/{len(fns)} passed")
