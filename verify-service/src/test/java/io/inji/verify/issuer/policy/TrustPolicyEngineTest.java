package io.inji.verify.issuer.policy;

import io.inji.verify.issuer.model.*;
import org.junit.jupiter.api.Test;

import java.util.EnumMap;
import java.util.Map;
import java.util.Set;

import static io.inji.verify.issuer.model.CheckId.*;
import static org.junit.jupiter.api.Assertions.*;

class TrustPolicyEngineTest {

    private final TrustPolicyEngine engine = new TrustPolicyEngine();

    private static Map<CheckId, CheckResult> allPass() {
        Map<CheckId, CheckResult> m = new EnumMap<>(CheckId.class);
        for (CheckId id : CheckId.values()) m.put(id, CheckResult.pass(id, "OK", "ok"));
        return m;
    }

    @Test
    void trustedOnlyWhenEveryRequiredCheckPasses() {
        assertEquals(TrustStatus.TRUSTED, engine.evaluate(TrustPolicy.registryStrict(), allPass()).status());
    }

    @Test
    void notApplicableIsNeutralButMissingOrNotEvaluatedIsNot() {
        var m = allPass();
        m.put(DID_RESOLUTION, CheckResult.notApplicable(DID_RESOLUTION, "n/a"));
        assertEquals(TrustStatus.TRUSTED, engine.evaluate(TrustPolicy.registryStrict(), m).status());
        m.put(ACCREDITATION_VALID, CheckResult.notEvaluated(ACCREDITATION_VALID, "x"));
        assertEquals(TrustStatus.INCONCLUSIVE, engine.evaluate(TrustPolicy.registryStrict(), m).status());
        m.remove(ACCREDITATION_VALID);
        assertEquals(TrustStatus.INCONCLUSIVE, engine.evaluate(TrustPolicy.registryStrict(), m).status(), "a check that never ran is fail-closed");
    }

    @Test
    void failBeatsInconclusiveBecauseEvidenceBeatsMissingData() {
        var m = allPass();
        m.put(DID_RESOLUTION, CheckResult.inconclusive(DID_RESOLUTION, "DID_RESOLUTION_TIMEOUT", "t"));
        m.put(ISSUER_REGISTERED, CheckResult.fail(ISSUER_REGISTERED, "ISSUER_NOT_REGISTERED", "f"));
        TrustEvaluation e = engine.evaluate(TrustPolicy.registryStrict(), m);
        assertEquals(TrustStatus.UNTRUSTED, e.status());
        assertEquals(DisplayStatus.ISSUER_NOT_FOUND, e.displayStatus());
    }

    @Test
    void optionalChecksDoNotDecideTheOutcome() {
        var m = allPass();
        m.put(ISSUER_REGISTERED, CheckResult.fail(ISSUER_REGISTERED, "ISSUER_NOT_REGISTERED", "f"));
        m.put(ACCREDITATION_VALID, CheckResult.fail(ACCREDITATION_VALID, "ACCREDITATION_EXPIRED", "f"));
        assertEquals(TrustStatus.TRUSTED, engine.evaluate(TrustPolicy.cryptographicOnly(), m).status());
    }

    @Test
    void revokedOrSuspendedIsAlwaysUntrustedEvenWhenPolicyDoesNotRequireRegistry() {
        for (String reason : new String[]{"ISSUER_REVOKED", "ISSUER_SUSPENDED", "ISSUER_DEACTIVATED"}) {
            var m = allPass();
            m.put(ISSUER_ACTIVE, CheckResult.fail(ISSUER_ACTIVE, reason, "f"));
            TrustEvaluation e = engine.evaluate(TrustPolicy.cryptographicOnly(), m);
            assertEquals(TrustStatus.UNTRUSTED, e.status(), reason);
            assertTrue(e.failureReasons().contains(reason));
        }
        var m = allPass();
        m.put(ISSUER_ACTIVE, CheckResult.fail(ISSUER_ACTIVE, "ISSUER_REVOKED", "f"));
        assertEquals(DisplayStatus.ISSUER_REVOKED, engine.evaluate(TrustPolicy.cryptographicOnly(), m).displayStatus());
        m.put(ISSUER_ACTIVE, CheckResult.fail(ISSUER_ACTIVE, "ISSUER_SUSPENDED", "f"));
        assertEquals(DisplayStatus.ISSUER_SUSPENDED, engine.evaluate(TrustPolicy.cryptographicOnly(), m).displayStatus());
    }

    @Test
    void noPolicyCanSkipCryptographicBinding() {
        TrustPolicy lax = new TrustPolicy("lax", Set.of(ISSUER_REGISTERED), Set.of(), Set.of());
        assertTrue(lax.isRequired(SIGNATURE_KEY_AUTHORIZED));
        assertTrue(lax.isRequired(ISSUER_IDENTIFIER_VALID));
        var m = allPass();
        m.put(SIGNATURE_KEY_AUTHORIZED, CheckResult.fail(SIGNATURE_KEY_AUTHORIZED, "KEY_NOT_AUTHORIZED_FOR_ASSERTION", "f"));
        assertEquals(TrustStatus.UNTRUSTED, engine.evaluate(lax, m).status());
        assertEquals(TrustStatus.UNTRUSTED, engine.evaluate(new TrustPolicy("empty", Set.of(), Set.of(), Set.of()), m).status());
    }

    @Test
    void presetPoliciesMatchTheirDescriptions() {
        TrustPolicy a = TrustPolicy.registryStrict(), b = TrustPolicy.cryptographicOnly(), c = TrustPolicy.trustFramework(Set.of("fw"));
        assertTrue(a.isRequired(ISSUER_REGISTERED) && a.isRequired(ISSUER_ACTIVE) && a.isRequired(CREDENTIAL_TYPE_AUTHORIZED) && a.isRequired(ACCREDITATION_VALID));
        assertFalse(a.isRequired(TRUST_FRAMEWORK_VALID));
        assertTrue(b.isRequired(DID_RESOLUTION) && b.isRequired(PUBLIC_KEY_VALID));
        assertFalse(b.isRequired(ISSUER_REGISTERED));
        assertTrue(c.isRequired(TRUST_FRAMEWORK_VALID) && c.isRequired(ACCREDITATION_VALID));
        assertEquals(Set.of("fw"), c.approvedTrustFrameworks());
    }
}
