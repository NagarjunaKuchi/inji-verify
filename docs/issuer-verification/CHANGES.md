# Changes – Issuer Details Verification (Inji Verify, based on tag v0.17.0)

Branch: `feature/issuer-verification-v0.17.0` (one commit on top of the `v0.17.0` tag).

Documents in this folder:

| File | Purpose |
|---|---|
| `README.md` | Design, flow, API contract, configuration, limitations |
| `QA-HANDOVER.md` | Step-by-step test guide for QA (profiles, test matrix, exit criteria) |
| `Inji_Verify_Issuer_Verification.postman_collection.json` | Postman collection (folders 0–6) |
| `Inji_Verify_local.postman_environment.json` | Postman environment (`baseUrl`, `vc_valid`, `vc_tampered`, `*_json_string`) |
| `sample-static-registry.json` | Example static trust-registry file |
| `tools/make_fixtures.py` | Generates the registry fixture files used by the QA scenarios |
| `CHANGES.md` | This file |

## 1. Summary of behaviour

- Adds an optional issuer check that reports **cryptographic authenticity** and **organizational trust** separately. Overall result: `TRUSTED`, `UNTRUSTED` or `INCONCLUSIVE`. Failures of infrastructure (DID host or registry unreachable) give `INCONCLUSIVE`, never `UNTRUSTED`.
- **Off by default** (`inji.verify.issuer-verification.enabled=false`). When off, no issuer beans are created and every response is identical to the `v0.17.0` baseline.
- Runs only after the signature has been verified as valid, so a forged credential cannot trigger outbound DID or registry requests.
- Issuer metadata inside the credential is never trusted; metadata comes only from the configured registry.
- No database changes. No new Maven or npm dependencies.

## 2. API changes (all additive)

| Endpoint | Change |
|---|---|
| `POST /v1/verify/vc-verification` | New optional query parameter `verifyIssuer=true\|false`. Response gains optional `issuerVerification`. Without the parameter the original code path is used. |
| `POST /v1/verify/v2/vc-verification` | New optional request field `verifyIssuer`. Response gains optional `issuerVerification`. |

`issuerVerification` is omitted from the JSON when the check did not run. With `enforce=true` an untrusted issuer makes the legacy status `INVALID` and `/v2` `allChecksSuccessful=false`; the default is advisory (`enforce=false`).

## 3. Modified existing files

| File | Change |
|---|---|
| `verify-service/.../controller/VCVerificationController.java` | `verifyIssuer` query parameter on the legacy endpoint; absent → original 2-argument service call |
| `verify-service/.../services/VCVerificationService.java` | new overload `verify(vc, contentType, Boolean verifyIssuer)` |
| `verify-service/.../services/impl/VCVerificationServiceImpl.java` | optional (`required=false`) injected `IssuerVerificationService`; issuer step in `verify` and `verifyV2` |
| `verify-service/.../dto/verification/VCVerificationRequestDto.java` | optional `verifyIssuer`; explicit constructors replace `@AllArgsConstructor` (the 1-argument constructor used by the VP flow is kept) |
| `verify-service/.../dto/verification/VCVerificationResultDto.java` | optional `issuerVerification` (`NON_NULL`); explicit 5-argument constructor replaces `@AllArgsConstructor` |
| `verify-service/.../dto/verification/VCVerificationStatusDto.java` | optional `issuerVerification` (`NON_NULL`); explicit constructors replace `@AllArgsConstructor` |
| `verify-service/src/main/resources/application.properties` | new `inji.verify.issuer-verification.*` keys (all with environment-variable overrides, safe defaults) |
| `inji-verify-sdk/src/utils/api.ts` | `vcVerificationDetailed` (adds `?verifyIssuer=` only when set); `vcVerification` kept and delegates to it |
| `inji-verify-sdk/src/components/qrcode-verification/QRCodeVerification.tsx` | `verifyIssuer` prop; `issuerVerification` added to the `onVCProcessed` result only when present |
| `inji-verify-sdk/src/components/qrcode-verification/QRCodeVerification.types.ts` | `verifyIssuer` prop and issuer result types |
| `verify-ui/src/components/Home/VerificationSection/Result/index.tsx` | renders `IssuerVerificationSection` |
| `verify-ui/src/components/Home/VerificationSection/QrScanner.tsx`, `verify-ui/src/pages/Upload.tsx` | handler parameter type widened with optional `issuerVerification` |
| `verify-ui/src/types/data-types.ts` | issuer result types; optional field on `VerificationResult` |
| `verify-ui/src/locales/en.json` | `IssuerVerification` strings (other locales fall back to the default language) |

## 4. New files

| Location | Content |
|---|---|
| `verify-service/src/main/java/io/inji/verify/issuer/` (67 files) | `model`, `identifier`, `net` (SSRF-guarded HTTP), `crypto`, `did` (did:web, did:jwk), `registry` (static, REST, TRQP/Affinidi), `metadata` (TTL caches), `extract`, `policy` (A, B, C, D), `engine` (10 checks), `config`, `IssuerVerificationService` |
| `verify-service/src/test/java/io/inji/verify/issuer/` (19 files incl. wiring test) | unit and integration tests for the above |
| `verify-service/src/test/java/io/inji/verify/services/impl/VCVerificationServiceImplIssuerTest.java` | issuer step in legacy `verify` and `verifyV2` |
| `verify-service/src/test/java/io/inji/verify/controller/VCVerificationControllerIssuerTest.java` | parameter handling and JSON shape |
| `verify-ui/.../Result/IssuerVerificationSection.tsx` and its spec | UI section (renders nothing when the block is absent) |
| `docs/issuer-verification/**` | documents listed at the top |

## 5. Configuration (all under `inji.verify.issuer-verification.`)

`enabled` (false), `run-by-default` (true), `enforce` (false), `active-policy` (A; A = registry strict, B = DID cryptographic only, C = trust framework, D = registered + authorised only, or a custom policy name), `approved-trust-frameworks`, `clock-skew`, `did.*` (allowed hosts, private-host switch, timeouts, cache TTL), `registry.type` (`none`\|`static`\|`rest`\|`trqp`), `registry.*` (id, static file, REST/TRQP base URL, bearer token, TRQP authority id and action, allowed ports, timeouts, cache TTLs, max metadata age). Defaults and environment-variable names are in `application.properties`; semantics are in `README.md`.

## 6. Backward compatibility and rollback

- Feature disabled → no behavioural change; verified by `IssuerVerificationWiringTest` (response body is exactly `{"verificationStatus":"SUCCESS"}`).
- Existing constructors used by other code (`new VCVerificationRequestDto(String)`, `new VCVerificationResultDto(...5 args)`, `new VCVerificationStatusDto(status)`) are preserved.
- Rollback: set `INJI_VERIFY_ISSUER_VERIFICATION_ENABLED=false` and restart.
- Side effect to be aware of: when enabled with `run-by-default=true`, credentials inside VP submissions are also checked (and with `enforce=true` lower `allChecksSuccessful`); the issuer block is not added to VP result DTOs.

## 7. Test status on this branch

| Check | Result |
|---|---|
| `mvn test` in `verify-service` | 407 tests, 0 failures, 0 errors |
| SDK `tsc` / `npm run build` | passes (installed with `--no-package-lock`; `npm ci` already fails on the untouched tag) |
| UI `IssuerVerificationSection` spec | passes |
| UI existing Result specs, SDK Jest suite | fail identically on the untouched `v0.17.0` tag |
| End-to-end run against a running service, Postgres, a signed credential, a public `did:web` host, or a live Affinidi registry | **not done** |
| Postman collection executed | **not done** |

`vcverifier-jar` is mocked in the issuer integration tests, so real LDP / SD-JWT / CWT signature verification combined with the new step is untested. CWT credentials return `INCONCLUSIVE` (`UNSUPPORTED_CREDENTIAL_FORMAT`).
