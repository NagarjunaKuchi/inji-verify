package io.inji.verify.issuer.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.model.TrustStatus;
import io.inji.verify.services.impl.VCVerificationServiceImpl;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.jackson.JacksonAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Real Spring context wiring: the optional field injection in VCVerificationServiceImpl, the property binding,
 * and the real issuer engine (offline, via did:jwk) driven through the real legacy verify path.
 * The signature verifier is mocked: this test is about issuer verification, not vcverifier.
 */
class IssuerVerificationWiringTest {

    private static final String P = "inji.verify.issuer-verification.";

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(JacksonAutoConfiguration.class))
            .withUserConfiguration(IssuerVerificationConfig.class, VCVerificationServiceImpl.class)
            .withBean(CredentialsVerifier.class, () -> {
                CredentialsVerifier v = mock(CredentialsVerifier.class);
                VerificationResult ok = new VerificationResult(true, "", "");
                CredentialVerificationSummary summary = mock(CredentialVerificationSummary.class);
                when(summary.getVerificationResult()).thenReturn(ok);
                try {
                    when(v.verifyAndGetCredentialStatus(anyString(), any(CredentialFormat.class), anyList())).thenReturn(summary);
                } catch (Exception e) {
                    throw new IllegalStateException(e);
                }
                return v;
            })
            .withBean(PixelPass.class, () -> mock(PixelPass.class))
            .withPropertyValues("inji.verify.claims-with-meta-data=iss");

    private static String didJwk() throws Exception {
        KeyPair kp = java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] enc = kp.getPublic().getEncoded();
        String x = Base64.getUrlEncoder().withoutPadding().encodeToString(java.util.Arrays.copyOfRange(enc, enc.length - 32, enc.length));
        String jwk = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"" + x + "\"}";
        return "did:jwk:" + Base64.getUrlEncoder().withoutPadding().encodeToString(jwk.getBytes(StandardCharsets.UTF_8));
    }

    private static String vc(String did) {
        return "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\",\"NationalIdCredential\"],"
                + "\"issuer\":\"" + did + "\",\"proof\":{\"type\":\"Ed25519Signature2020\",\"proofPurpose\":\"assertionMethod\","
                + "\"verificationMethod\":\"" + did + "#0\"}}";
    }

    private static Path registryFor(Path dir, String did) throws Exception {
        String json = "{\"registryId\":\"wiring\",\"issuers\":[{\"issuerId\":\"" + did + "\",\"name\":\"Wiring Authority\","
                + "\"status\":\"ACTIVE\",\"validFrom\":\"2020-01-01T00:00:00Z\",\"validUntil\":\"2099-12-31T23:59:59Z\","
                + "\"accreditations\":[{\"id\":\"a1\",\"authority\":\"Board\",\"status\":\"ACTIVE\","
                + "\"validFrom\":\"2020-01-01T00:00:00Z\",\"validUntil\":\"2099-12-31T23:59:59Z\"}],"
                + "\"trustFrameworks\":[\"fw\"],\"authorizedCredentialTypes\":[\"NationalIdCredential\"],\"asOf\":\"2026-01-01T00:00:00Z\"}]}";
        Path f = dir.resolve("registry.json");
        Files.writeString(f, json);
        return f;
    }

    @Test
    void featureDisabledByDefault_noBeanAndNoIssuerBlock() {
        runner.run(ctx -> {
            assertNull(ctx.getBeanProvider(IssuerVerificationService.class).getIfAvailable());
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc("did:jwk:x"), "application/ldp+json", true);
            assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
            assertNull(dto.getIssuerVerification());
            // and the serialised response is exactly what existing clients receive today
            assertEquals("{\"verificationStatus\":\"SUCCESS\"}", new ObjectMapper().writeValueAsString(dto));
        });
    }

    @Test
    void enabled_policyB_didJwk_isTrustedWithoutRegistry() throws Exception {
        String did = didJwk();
        runner.withPropertyValues(P + "enabled=true", P + "active-policy=B").run(ctx -> {
            assertNotNull(ctx.getBeanProvider(IssuerVerificationService.class).getIfAvailable());
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc(did), "application/ldp+json", true);
            assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
            assertNotNull(dto.getIssuerVerification());
            assertEquals(TrustStatus.TRUSTED, dto.getIssuerVerification().overallStatus());
        });
    }

    @Test
    void enabled_policyA_withoutRegistry_failsClosedToInconclusive_andNeverTrusted() throws Exception {
        String did = didJwk();
        runner.withPropertyValues(P + "enabled=true", P + "active-policy=A").run(ctx -> {
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc(did), "application/ldp+json", true);
            assertNotEquals(TrustStatus.TRUSTED, dto.getIssuerVerification().overallStatus());
            assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus(), "advisory mode must not change the signature result");
        });
    }

    @Test
    void enabled_policyA_staticRegistry_activeIssuer_isTrusted(@TempDir Path dir) throws Exception {
        String did = didJwk();
        runner.withPropertyValues(P + "enabled=true", P + "active-policy=D",
                P + "registry.type=static", P + "registry.static-file=" + registryFor(dir, did)).run(ctx -> {
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc(did), "application/ldp+json", true);
            assertEquals(TrustStatus.TRUSTED, dto.getIssuerVerification().overallStatus(), String.valueOf(dto.getIssuerVerification()));
        });
    }

    @Test
    void enforce_unregisteredIssuer_makesLegacyStatusInvalid(@TempDir Path dir) throws Exception {
        String registered = didJwk();
        String other = didJwk();
        runner.withPropertyValues(P + "enabled=true", P + "active-policy=D", P + "enforce=true",
                P + "registry.type=static", P + "registry.static-file=" + registryFor(dir, registered)).run(ctx -> {
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc(other), "application/ldp+json", true);
            assertEquals(VerificationStatus.INVALID, dto.getVerificationStatus());
            assertEquals(TrustStatus.UNTRUSTED, dto.getIssuerVerification().overallStatus());
        });
    }

    @Test
    void requestFlagFalse_overridesRunByDefault() throws Exception {
        String did = didJwk();
        runner.withPropertyValues(P + "enabled=true", P + "active-policy=B").run(ctx -> {
            VCVerificationStatusDto dto = ctx.getBean(VCVerificationServiceImpl.class).verify(vc(did), "application/ldp+json", false);
            assertNull(dto.getIssuerVerification());
        });
    }

    @Test
    void unknownRegistryType_failsStartup() {
        runner.withPropertyValues(P + "enabled=true", P + "registry.type=bogus").run(ctx -> assertNotNull(ctx.getStartupFailure()));
    }

    @Test
    void ctorStillSupportsDirectConstruction() {
        assertNotNull(new VCVerificationServiceImpl(mock(CredentialsVerifier.class), mock(PixelPass.class)));
    }
}
