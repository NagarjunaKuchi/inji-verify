# QA Handover – Issuer Details Verification (Inji Verify, based on tag v0.17.0)

Branch: `feature/issuer-verification-v0.17.0`. Read `README.md` in this folder for the design; this file is the test guide.

> **Status before QA starts:** `mvn test` in `verify-service` passes on this branch (0 failures, 0 errors), including a Spring-context wiring test that runs the real issuer engine offline (`did:jwk`). What has NOT been done: the service was never started against Postgres, no real signed credential was verified end to end, no public `did:web` host or live Affinidi registry was used, and the Postman collection has not been executed. Your first run of the matrix below is therefore also the first end-to-end run.

## 1. What is being tested

An optional check on `POST /vc-verification` (legacy) and `POST /v2/vc-verification` that answers two separate questions:

1. **Cryptographic authenticity** – was the credential signed by a key that belongs to the issuer identifier (did:web DID document)?
2. **Organizational trust** – is that issuer registered, active, accredited and authorised for this credential type, according to a trust registry configured by the operator (never from data inside the credential)?

Result values: `TRUSTED`, `UNTRUSTED`, `INCONCLUSIVE`. A registry/network outage must give `INCONCLUSIVE`, never `UNTRUSTED`. A valid signature alone must never give `TRUSTED` under a registry policy.

| Area | Change |
|---|---|
| API | `POST /v1/verify/vc-verification[?verifyIssuer=true\|false]` and `POST /v1/verify/v2/vc-verification` (JSON field `verifyIssuer`); responses gain optional `issuerVerification` |
| Default | Feature **off** (`enabled=false`): responses must be identical to the baseline build |
| Config | `inji.verify.issuer-verification.*` (env vars listed in section 5) |
| DB | none |
| SDK/UI | `verifyIssuer` prop; "Issuer Verification" section on the result page (only when the response has `issuerVerification`) |

Scope limits: the extractor reads LDP and JWT/SD-JWT credentials; CWT gives `INCONCLUSIVE` (`UNSUPPORTED_CREDENTIAL_FORMAT`). Issuer ids `did:web` and `did:jwk`; other DID methods give `INCONCLUSIVE`. The legacy endpoint chooses the credential format from the `Content-Type` header (the collection uses `application/json`, which is verified as LDP).

## 2. Gate: build and automated tests (dev/QA lead)

Run from the repo root with the project's normal Maven build, and record the result in the test report:

1. Build `verify-service` and run its unit tests (`mvn test` in `verify-service`). Expected: compiles; all tests pass, including `io.inji.verify.issuer.**`, `VCVerificationServiceImplIssuerTest`, `VCVerificationControllerIssuerTest` and `IssuerVerificationWiringTest`.
2. If the UI is in scope: in `verify-ui` run `npm test`. Known: 3 existing Result specs (`index.spec`, `VcCardDisplay.spec`, `ResultSummary.spec`) and some `tsc` errors already fail on the untouched `v0.17.0` tag (`window._env_` is undefined in the test environment) – compare against a baseline run, do not count them as regressions.
3. SDK (`inji-verify-sdk`): `npm ci` fails on the untouched tag (lockfile out of sync); use `npm install --no-package-lock`, then `npm run build`. It builds. The existing Jest suite fails to parse under that install with or without this change.

## 3. Test data you must prepare

The authoring team cannot supply signed credentials. You need:

- **A validly signed LDP VC** (`vc_valid`) whose `issuer` is a `did:web` DID that the *service* can resolve over public HTTPS (the SSRF guard blocks private/loopback addresses, plain http and redirects; for a closed lab only, set `…_DID_ALLOW_PRIVATE_HOSTS=true` – never in a shared or production environment).
- **A tampered copy** (`vc_tampered`): same VC with one claim value changed (signature must fail).
- The issuer's **public JWK** in a file (`signing-key.public.jwk.json`), and the VC's `type` values other than `VerifiableCredential`.

Confirm first, with the baseline build or with `enabled=false`, that `vc_valid` returns `SUCCESS` and `vc_tampered` returns `INVALID`. If not, fix the test data before continuing.

### Generate registry fixtures

```
python3 tools/make_fixtures.py --issuer-did did:web:<your-issuer> \
   --credential-type <Type1> [--credential-type <Type2> ...] \
   --jwk signing-key.public.jwk.json --out fixtures/
```
Every non-`VerifiableCredential` type in the VC must be passed – the issuer is authorised only if **all** of them are listed. Output files: `registry-active`, `-suspended`, `-revoked`, `-deactivated`, `-accreditation-expired`, `-type-not-authorized`, `-framework-other`, `-issuer-absent` (`.json`). `sample-static-registry.json` shows the format.

Note: registry `keyThumbprints` are compared only for https issuers. For `did:web`, the key is bound through the DID document, so there is no registry-only "wrong key" scenario.

## 4. Import Postman

Import `Inji_Verify_Issuer_Verification.postman_collection.json` and `Inji_Verify_local.postman_environment.json`. In the environment set `baseUrl` (default `http://localhost:8080/v1/verify`), `vc_valid` (single-line JSON) and `vc_tampered`; for folder 6 (`/v2`) also `vc_valid_json_string` and `vc_tampered_json_string` (the same credentials as JSON string literals, because `/v2` takes `verifiableCredential` as a string). Each request states the server profile it needs; run a folder only after the service is restarted in that profile. The collection variable `featureEnabled` (default `true`) should be set to `false` when running profile P0.

## 5. Server profiles

Set via environment variables (docker-compose `environment:` of `verify-service`, or the deployment config). Mount a fixture file into the container and point `REGISTRY_STATIC_FILE` at the in-container path.

| Profile | `INJI_VERIFY_ISSUER_VERIFICATION_` variables |
|---|---|
| P0 disabled | `ENABLED=false` (or unset) |
| P1 policy A, static | `ENABLED=true`, `POLICY=A`, `REGISTRY_TYPE=static`, `REGISTRY_STATIC_FILE=/config/registry.json` (copy of the fixture under test) |
| P2 policy A, no registry | `ENABLED=true`, `POLICY=A`, `REGISTRY_TYPE=none` |
| P3 policy B | `ENABLED=true`, `POLICY=B`, `REGISTRY_TYPE=none` (or static) |
| P4 policy C | `ENABLED=true`, `POLICY=C`, `APPROVED_TRUST_FRAMEWORKS=qa-framework`, `REGISTRY_TYPE=static` (and a run with the variable empty) |
| P5 REST registry | `ENABLED=true`, `POLICY=A`, `REGISTRY_TYPE=rest`, `REGISTRY_REST_BASE_URL=<url>`; contract: `GET {base}/issuers/{url-encoded issuerId}` → 200 with the same record as the static file, 404 if unknown. You need a stub that serves it (any HTTP mock). |
| P6 enforce | as P1 plus `ENFORCE=true` |
| P7 TRQP (Affinidi) | `ENABLED=true`, `POLICY=D`, `REGISTRY_TYPE=trqp`, `REGISTRY_REST_BASE_URL=https://<registry-host>`, `REGISTRY_TRQP_AUTHORITY_ID=<authority DID>`, optional `REGISTRY_TRQP_ACTION` (default `issue`), `REGISTRY_ALLOWED_PORTS` (e.g. `443,3232`), `REGISTRY_ALLOW_PRIVATE_HOSTS=true` only for an internal registry |

The static registry is read at start-up: **restart the service after changing the fixture**. `RUN_BY_DEFAULT` defaults to `true`, so with the feature enabled a request without the parameter also runs the issuer check.

## 6. Test matrix

| ID | Profile / fixture | Request | Expected |
|---|---|---|---|
| B1 | P0 | `vc_valid`, no param | 200, `{"verificationStatus":"SUCCESS"}` only – no `issuerVerification` key |
| B2 | any | `vc_tampered` | `INVALID`, no `issuerVerification`, and **no outbound DID/registry request** in service logs |
| B3 | any | empty body | 400 (unchanged) |
| P1 | enabled | `?verifyIssuer=false` | no `issuerVerification` |
| P2 | enabled | `?verifyIssuer=true` | `issuerVerification` present |
| P3 | enabled | `?verifyIssuer=abc` | 400 |
| A1 | P1 + active | `?verifyIssuer=true` | `TRUSTED`, display `TRUSTED_ISSUER`, `cryptographicAuthenticity=VERIFIED`, `organizationalTrust=TRUSTED`, `issuerName` equals the registry's name |
| A2 | P1 + suspended | | `UNTRUSTED`, `ISSUER_SUSPENDED` |
| A3 | P1 + revoked | | `UNTRUSTED`, `ISSUER_REVOKED` |
| A4 | P1 + deactivated | | `UNTRUSTED`; check `ISSUER_ACTIVE` = FAIL |
| A5 | P1 + accreditation-expired | | `UNTRUSTED`; `ACCREDITATION_VALID` = FAIL |
| A6 | P1 + type-not-authorized | | `UNTRUSTED`; `CREDENTIAL_TYPE_AUTHORIZED` = FAIL |
| A7 | P1 + issuer-absent | | `UNTRUSTED`, `ISSUER_NOT_FOUND` |
| A8 | P2 | | `INCONCLUSIVE` (never `TRUSTED`) |
| B-1 | P3 no registry | | `TRUSTED`, `organizationalTrust=NOT_EVALUATED` |
| B-2 | P3 + revoked | | `UNTRUSTED` (registry revocation overrides) |
| C1 | P4 + active | | `TRUSTED` |
| C2 | P4 + framework-other | | `UNTRUSTED`; `TRUST_FRAMEWORK_VALID` = FAIL |
| C3 | P4, no approved frameworks | | `INCONCLUSIVE` (fail closed) |
| R1 | P5, stub stopped | | `INCONCLUSIVE`, display `VERIFICATION_INCONCLUSIVE`; never `UNTRUSTED` |
| R2 | P5, stub back up | | `TRUSTED` again; outage not cached beyond TTL |
| T1 | P7, record exists: (authority, issuer DID, `issue`, each VC type) | `?verifyIssuer=true` | `TRUSTED`; `issuerName` empty (TRQP has no names); registry queried with the exact strings in the record |
| T2 | P7, issuer has no record / not authorised for the type | | `UNTRUSTED`, `ISSUER_NOT_FOUND` (TRQP cannot say whether unknown, suspended or revoked) |
| T3 | P7, one of two VC types not authorised | | `UNTRUSTED`; `CREDENTIAL_TYPE_AUTHORIZED` = FAIL |
| T4 | P7, registry stopped / wrong port | | `INCONCLUSIVE`, never `UNTRUSTED` |
| T5 | P7, wrong `REGISTRY_REST_BASE_URL` path (registry returns a non-JSON 404) | | `INCONCLUSIVE` (configuration error, not evidence against the issuer) |
| T6 | P7 with `POLICY=A` | | not `TRUSTED` (TRQP carries no accreditation data) |
| T7 | P7, `REGISTRY_TRQP_AUTHORITY_ID` unset | | service **fails to start** with "TRQP authority id is required" |
| E1 | P6 + suspended | | `verificationStatus=INVALID` and `issuerVerification.overallStatus=UNTRUSTED` |
| E2 | P6 + active | | `SUCCESS`, `TRUSTED` |
| E3 | P6 + `vc_valid` expired VC | | `EXPIRED` stays `EXPIRED` |

Postman folder 5 implements T1–T4, T6; T5 and T7 are manual. Folder 2 implements A1–A8, folder 3 B-1…C3, folder 4 R1/E1/E2, folder 0–1 the baseline and parameter cases. Folder 6 covers `/v2/vc-verification`: 6.1 default, 6.2 opt-in, 6.3 opt-out, 6.4 enforce (`allChecksSuccessful=false`, signature checks unchanged), 6.5 tampered credential (no `issuerVerification`, no outbound requests).

### TRQP / Affinidi notes for QA

- Create the registry records using the registry's own documentation (its CSV/Redis/DynamoDB format is not covered here): one record per `(authority_id, entity_id = issuer DID, action = issue, resource = credential type string)`. `resource` must equal the VC's `type` entry exactly (case-sensitive).
- **Please record, from the running registry, what it returns** for (a) an authorised tuple, (b) an unknown issuer and (c) a revoked/removed record – status code and body. Dev has not seen a live instance; send these captures back so the adapter can be confirmed or fixed.
- The registry must be reachable over **https with a DNS name** from the service (IP-literal and plain http are refused by the SSRF guard).
- Registry queries are cached per (issuer, type set) for the registry cache TTL (default 5 min; denials 1 min). After changing a record, wait for the TTL or restart before re-testing.

## 7. Non-functional checks

- **Information leakage:** in every response and in the UI, confirm there are no stack traces, internal hosts/IPs, registry URLs, tokens or resolver errors. Messages are generic. (Known item for review: `trustRegistry.registryId` is returned in the JSON; the UI does not show it.)
- **Fail-safe:** with the feature enabled, break the registry (P5 stub down, or wrong `REGISTRY_REST_BASE_URL`) and the DID host; the endpoint must still answer 200 with a normal `verificationStatus` and `issuerVerification.overallStatus=INCONCLUSIVE`. It must never return 5xx because of issuer verification.
- **Latency:** compare response time with P0 and with P1; DID and registry connect/read timeouts default to 3s/5s. Repeat the same request: the second call should be faster (cache TTL 5m for successes).
- **Rollback:** set `ENABLED=false` and restart; behaviour must return to B1.
- **Security tests QA cannot do via the API:** SSRF (loopback, link-local, private ranges, redirects, oversized responses), malicious DID documents and key substitution need a validly signed credential for a hostile issuer, so they are covered by unit tests (`UrlSafetyPolicyTest`, `SafeHttpFetcherTest`, `DidTest`, `IssuerVerificationEngineTest`). QA should confirm those tests run and pass in step 2 rather than try to reproduce them manually.

## 8. UI check (only with an SDK build that includes this change)

With the UI pointing to a service in P1: scan/upload `vc_valid` → result page shows a status badge, issuer name/type/jurisdiction and a "Show checks" toggle; expanding lists each check with a symbol and message. With P0 the section must not appear. With `INCONCLUSIVE` the note "does not mean the issuer is untrustworthy" is shown. English strings only; other languages fall back to the default language.

## 9. Known limitations / not yet verified

- No end-to-end run against a real service yet (see top of this file).
- Issuer extraction: LDP and JWT/SD-JWT only (CWT → `INCONCLUSIVE`); `did:web`/`did:jwk` only; static registry reloads on restart only.
- With the feature enabled and `run-by-default=true`, credentials inside VP submissions are also checked (and, with `enforce=true`, lower `allChecksSuccessful`); the issuer block is not added to VP result DTOs.
- Registry responses are not signed (trust relies on TLS and the chosen registry).
- Library behaviour (`vcverifier-jar` 1.7.0 at this tag) was not independently examined; it is mocked in the automated issuer tests.
- The SDK builds but has no test for the new code; three existing UI Result specs fail on the untouched tag, so the `Result` page wiring has no automated test.

## 10. Exit criteria

All matrix rows pass; B1–B3 pass on a build with the feature disabled (no regression); no leakage findings; gate in section 2 green; no 5xx observed under registry/DID failure.
