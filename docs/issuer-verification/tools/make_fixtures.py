#!/usr/bin/env python3
"""Generate static-registry fixture files for the QA scenarios.

Usage:
  make_fixtures.py --issuer-did did:web:issuer.example.org --credential-type UniversityDegreeCredential [--credential-type Other] \
                   --jwk signing-key.public.jwk.json --out fixtures/

--jwk is the PUBLIC JWK of the key that signed the test credential (EC, OKP or RSA). Private members are rejected.
Note: keyThumbprints in the registry are compared only for https issuers; for did:web issuers the key is bound via the DID document.
Stdlib only. The thumbprint is the RFC 7638 SHA-256 JWK thumbprint, base64url without padding.
"""
import argparse, base64, hashlib, json, os, sys

REQUIRED = {"EC": ["crv", "kty", "x", "y"], "OKP": ["crv", "kty", "x"], "RSA": ["e", "kty", "n"]}


def thumbprint(jwk):
    kty = jwk.get("kty")
    if kty not in REQUIRED:
        sys.exit("unsupported kty: %r" % kty)
    if any(k in jwk for k in ("d", "p", "q", "dp", "dq", "qi", "k")):
        sys.exit("refusing a JWK that contains private key material")
    members = {k: jwk[k] for k in REQUIRED[kty]}
    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=").decode()


def record(did, ctype, tp, **over):
    r = {
        "issuerId": did, "name": "QA Test Authority", "legalName": "QA Test Authority Ltd",
        "organizationType": "Government", "jurisdiction": "IN", "status": "ACTIVE",
        "validFrom": "2020-01-01T00:00:00Z", "validUntil": "2099-12-31T23:59:59Z",
        "accreditations": [{"id": "acc-qa-1", "authority": "QA Accreditation Board", "status": "ACTIVE",
                            "validFrom": "2020-01-01T00:00:00Z", "validUntil": "2099-12-31T23:59:59Z"}],
        "trustFrameworks": ["qa-framework"], "authorizedCredentialTypes": list(ctype), "keyThumbprints": [tp],
    }
    r.update(over)
    return r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--issuer-did", required=True)
    ap.add_argument("--credential-type", required=True, action="append",
                    help="repeat for every non-VerifiableCredential type in the test VC; ALL must be authorised")
    ap.add_argument("--jwk", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tp = thumbprint(json.load(open(a.jwk)))
    d, t = a.issuer_did, a.credential_type
    expired = [{"id": "acc-qa-1", "authority": "QA Accreditation Board", "status": "ACTIVE",
                "validFrom": "2020-01-01T00:00:00Z", "validUntil": "2021-01-01T00:00:00Z"}]
    scenarios = {
        "registry-active.json": record(d, t, tp),
        "registry-suspended.json": record(d, t, tp, status="SUSPENDED"),
        "registry-revoked.json": record(d, t, tp, status="REVOKED"),
        "registry-deactivated.json": record(d, t, tp, status="DEACTIVATED"),
        "registry-accreditation-expired.json": record(d, t, tp, accreditations=expired),
        "registry-type-not-authorized.json": record(d, t, tp, authorizedCredentialTypes=["SomeOtherCredential"]),
        "registry-framework-other.json": record(d, t, tp, trustFrameworks=["some-other-framework"]),
    }
    os.makedirs(a.out, exist_ok=True)
    for name, rec in scenarios.items():
        with open(os.path.join(a.out, name), "w") as f:
            json.dump({"registryId": "qa-registry", "issuers": [rec]}, f, indent=2)
    # issuer not present at all
    with open(os.path.join(a.out, "registry-issuer-absent.json"), "w") as f:
        json.dump({"registryId": "qa-registry", "issuers": [record("did:web:someone-else.example.org", t, tp)]}, f, indent=2)
    print("thumbprint:", tp)
    print("wrote %d fixtures to %s" % (len(scenarios) + 1, a.out))


if __name__ == "__main__":
    main()
