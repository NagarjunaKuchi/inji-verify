# QA Handover – Issuer Details Verification (Inji Verify, based on tag v0.14.0)

Branch: `feature/issuer-verification` (patch: `issuer-verification-v0.14.0.patch`). Read `README.md` in this folder for the design; this file is the test guide.

> **Status before QA starts:** the code has NOT been built with Maven and the Spring/Mockito tests have NOT been run (the authoring environment could not reach Maven Central). Step 2 below is therefore the first gate. Treat any compile or unit-test failure there as a dev defect, not a QA finding.

## 1. What is being tested

An optional check on `POST /vc-verification` that answers two separate questions:

1. **Cryptographic authenticity** – was the credential signed by a key that belongs to the issuer identifier (did:web DID document)?
2. **Organizational trust** – is that issuer registered, active, accredited and authorised for this credential type, according to a trust registry configured by the operator (never from data inside the credential)?

Result values: `TRUSTED`, `UNTRUSTED`, `INCONCLUSIVE`. A registry/network outage must give `INCONCLUSIVE`, never `UNTRUSTED`. A valid signature alone must never give `TRUSTED` under a registry policy.

| Area | Change |
|---|---|
| API | `POST /v1/verify/vc-verification[?verifyIssuer=true\|false]`; response gains optional `issuerVerification` |
| Default | Feature **off** (`enabled=false`): responses must be identical to the baseline build |
| Config | `inji.verify.issuer-verification.*` (env vars listed in section 5) |
| DB | none |
| SDK/UI | `verifyIssuer` prop; "Issuer Verification" section on the result page (only when the response has `issuerVerification`) |

Scope limits at this tag: LDP VCs only (the endpoint verifies as `LDP_VC`); issuer ids `did:web` and `did:jwk`; other DID methods give `INCONCLUSIVE`.

## 2. Gate: build and automated tests (dev/QA lead)

Run from the repo root with the project's normal Maven build, and record the result in the test report:

1. Build `verify-service` and run its unit tests (`mvn test` in `verify-service`). Expected: compiles; all pre-existing tests pass; new tests pass:
   - `io.inji.verify.issuer.**` (≈104 tests; these passed locally against a JUnit shim)
   - `VCVerificationServiceImplIssuerTest`, `VCVerificationControllerIssuerTest`, `IssuerVerificationConfigTest` (never run with real Spring/Mockito – first real run)
2. If the UI is in scope: in `verify-ui` run `npm test`. Known: 3 existing Result specs (`index.spec`, `VcCardDisplay.spec`, `ResultSummary.spec`) and some `tsc` checks already fail on the untouched `v0.14.0` tag – compare against a baseline run, do not count them as regressions.
3. SDK (`inji-verify-sdk`): install dependencies and build; the SDK change has not been compiled.

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

Import `Inji_Verify_Issuer_Verification.postman_collection.json` and `Inji_Verify_local.postman_environment.json`. In the environment set `baseUrl` (default `http://localhost:8080/v1/verify`), `vc_valid` (single-line JSON) and `vc_tampered`. Each request states the server profile it needs; run a folder only after the service is restarted in that profile. The collection variable `featureEnabled` (default `true`) should be set to `false` when running profile P0.

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
| E1 | P6 + suspended | | `verificationStatus=INVALID` and `issuerVerification.overallStatus=UNTRUSTED` |
| E2 | P6 + active | | `SUCCESS`, `TRUSTED` |
| E3 | P6 + `vc_valid` expired VC | | `EXPIRED` stays `EXPIRED` |

Postman folder 2 implements A1–A8, folder 3 B-1…C3, folder 4 R1/E1/E2, folder 0–1 the baseline and parameter cases.

## 7. Non-functional checks

- **Information leakage:** in every response and in the UI, confirm there are no stack traces, internal hosts/IPs, registry URLs, tokens or resolver errors. Messages are generic. (Known item for review: `trustRegistry.registryId` is returned in the JSON; the UI does not show it.)
- **Fail-safe:** with the feature enabled, break the registry (P5 stub down, or wrong `REGISTRY_REST_BASE_URL`) and the DID host; the endpoint must still answer 200 with a normal `verificationStatus` and `issuerVerification.overallStatus=INCONCLUSIVE`. It must never return 5xx because of issuer verification.
- **Latency:** compare response time with P0 and with P1; DID and registry connect/read timeouts default to 3s/5s. Repeat the same request: the second call should be faster (cache TTL 5m for successes).
- **Rollback:** set `ENABLED=false` and restart; behaviour must return to B1.
- **Security tests QA cannot do via the API:** SSRF (loopback, link-local, private ranges, redirects, oversized responses), malicious DID documents and key substitution need a validly signed credential for a hostile issuer, so they are covered by unit tests (`UrlSafetyPolicyTest`, `SafeHttpFetcherTest`, `DidTest`, `IssuerVerificationEngineTest`). QA should confirm those tests run and pass in step 2 rather than try to reproduce them manually.

## 8. UI check (only with an SDK build that includes this change)

With the UI pointing to a service in P1: scan/upload `vc_valid` → result page shows a status badge, issuer name/type/jurisdiction and a "Show checks" toggle; expanding lists each check with a symbol and message. With P0 the section must not appear. With `INCONCLUSIVE` the note "does not mean the issuer is untrustworthy" is shown. English strings only; other languages fall back to the default language.

## 9. Known limitations / not yet verified

- Maven build and Spring/Mockito tests not yet run (see gate).
- LDP only; `did:web`/`did:jwk` only; static registry reloads on restart only.
- Registry responses are not signed (trust relies on TLS and the chosen registry).
- Library behaviour (`vcverifier-jar` 1.3.0 at this tag) was not independently examined.
- SDK not compiled; three existing UI Result specs fail on the untouched tag.

## 10. Exit criteria

All matrix rows pass; B1–B3 pass on a build with the feature disabled (no regression); no leakage findings; gate in section 2 green; no 5xx observed under registry/DID failure.
