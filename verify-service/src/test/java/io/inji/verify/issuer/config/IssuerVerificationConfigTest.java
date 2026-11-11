package io.inji.verify.issuer.config;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.policy.TrustPolicy;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class IssuerVerificationConfigTest {

    private static IssuerVerificationProperties props(String policy) {
        IssuerVerificationProperties p = new IssuerVerificationProperties();
        p.setActivePolicy(policy);
        return p;
    }

    @Test
    void presetsResolve() {
        assertEquals("A", IssuerVerificationConfig.resolvePolicy(props("A")).name());
        assertEquals("B", IssuerVerificationConfig.resolvePolicy(props("B")).name());
        assertEquals("C", IssuerVerificationConfig.resolvePolicy(props("C")).name());
        assertEquals("D", IssuerVerificationConfig.resolvePolicy(props("D")).name());
    }

    @Test
    void unknownPolicyFailsFast() {
        assertThrows(IllegalStateException.class, () -> IssuerVerificationConfig.resolvePolicy(props("Z")));
    }

    @Test
    void customPolicyWithoutRequiredChecksIsRejected() {
        IssuerVerificationProperties p = props("custom");
        p.getPolicies().put("custom", new IssuerVerificationProperties.Policy());
        assertThrows(IllegalStateException.class, () -> IssuerVerificationConfig.resolvePolicy(p));
    }

    @Test
    void customPolicyAlwaysRequiresCryptographicBinding() {
        IssuerVerificationProperties p = props("custom");
        IssuerVerificationProperties.Policy custom = new IssuerVerificationProperties.Policy();
        custom.setRequired(Set.of(CheckId.ISSUER_REGISTERED));
        p.getPolicies().put("custom", custom);

        TrustPolicy resolved = IssuerVerificationConfig.resolvePolicy(p);

        assertTrue(resolved.isRequired(CheckId.ISSUER_REGISTERED));
        assertTrue(resolved.isRequired(CheckId.ISSUER_IDENTIFIER_VALID));
        assertTrue(resolved.isRequired(CheckId.SIGNATURE_KEY_AUTHORIZED));
    }
}
