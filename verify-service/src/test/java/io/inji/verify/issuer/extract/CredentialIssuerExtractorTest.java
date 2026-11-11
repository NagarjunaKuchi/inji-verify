package io.inji.verify.issuer.extract;

import io.inji.verify.issuer.crypto.KeyMaterial;
import io.inji.verify.issuer.model.CredentialIssuerContext;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class CredentialIssuerExtractorTest {

    /** Self-signed EC P-256 test certificate (DER, base64). */
    static final String CERT = "MIIBgDCCASegAwIBAgIUTAM5jkbxnB/E5Xkuwz5u8u5dJYEwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAwwLdGVzdC1pc3N1ZXIwHhcNMjYxMTA2MDM1MzQ0WhcNMzYxMTAzMDM1MzQ0WjAWMRQwEgYDVQQDDAt0ZXN0LWlzc3VlcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJAJ/Pa1Ek2NJhWn7tzqmUqrCchZcSa7zKKhJHHUbn4RaM9jZlgaFFKg02Qz4Dd/YMaztnoQVMp4SiQRDHw71w+jUzBRMB0GA1UdDgQWBBTsUfv65f4Ix5KaGCI4Zht2NsBUfzAfBgNVHSMEGDAWgBTsUfv65f4Ix5KaGCI4Zht2NsBUfzAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0cAMEQCIAXjpt4GBfAYsRA/RQQgrcMV8xNsieGPyp8VYlv9Sbb8AiB8qHO8OB1EfTaqWypAa7sm0+7jQv/fumsPy1vwgxRqYw==";

    private final CredentialIssuerExtractor extractor = new CredentialIssuerExtractor();

    private static String b64(String s) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(s.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void extractsOnlyIdTypesAndKeyReferenceFromLdp() throws Exception {
        String vc = "{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":[\"VerifiableCredential\",\"NationalIdCredential\"],"
                + "\"issuer\":\"did:web:issuer.example.org\",\"proof\":{\"type\":\"Ed25519Signature2020\",\"proofPurpose\":\"assertionMethod\","
                + "\"verificationMethod\":\"did:web:issuer.example.org#key-0\"}}";
        CredentialIssuerContext c = extractor.extract(vc);
        assertEquals("did:web:issuer.example.org", c.issuerId());
        assertEquals(java.util.List.of("VerifiableCredential", "NationalIdCredential"), c.credentialTypes());
        assertEquals("did:web:issuer.example.org#key-0", c.signingKeyId());
        assertEquals("assertionMethod", c.proofPurpose());
        assertNull(c.signingKeyThumbprint());
    }

    @Test
    void supportsIssuerObjectsAndProofArraysAndIgnoresEmbeddedIssuerMetadata() throws Exception {
        String vc = "{\"type\":\"Foo\",\"issuer\":{\"id\":\"did:web:issuer.example.org\",\"name\":\"Totally Legit Ministry\",\"jurisdiction\":\"XX\"},"
                + "\"proof\":[{\"proofPurpose\":\"assertionMethod\",\"verificationMethod\":{\"id\":\"did:web:issuer.example.org#k\"}}]}";
        CredentialIssuerContext c = extractor.extract(vc);
        assertEquals("did:web:issuer.example.org", c.issuerId());
        assertEquals("did:web:issuer.example.org#k", c.signingKeyId());
        assertEquals(java.util.List.of("Foo"), c.credentialTypes());
        assertFalse(c.toString().contains("Totally Legit"), "embedded name must not be carried forward");
    }

    @Test
    void missingIssuerIsReportedAsNullNotAsAnError() throws Exception {
        assertNull(extractor.extract("{\"type\":[\"VerifiableCredential\"]}").issuerId());
    }

    @Test
    void extractsIssuerTypeAndLeafCertKeyIdentityFromSdJwt() throws Exception {
        String header = b64("{\"alg\":\"ES256\",\"typ\":\"vc+sd-jwt\",\"x5c\":[\"" + CERT + "\"]}");
        String payload = b64("{\"iss\":\"did:web:issuer.example.org\",\"vct\":\"NationalIdCredential\"}");
        CredentialIssuerContext c = extractor.extract(header + "." + payload + ".c2ln~WyJzYWx0IiwiYSIsMV0~");
        assertEquals("did:web:issuer.example.org", c.issuerId());
        assertEquals(java.util.List.of("NationalIdCredential"), c.credentialTypes());

        byte[] spki = java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(Base64.getDecoder().decode(CERT))).getPublicKey().getEncoded();
        byte[] x = Arrays.copyOfRange(spki, spki.length - 64, spki.length - 32), y = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
        Base64.Encoder e = Base64.getUrlEncoder().withoutPadding();
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + e.encodeToString(x) + "\",\"y\":\"" + e.encodeToString(y) + "\"}";
        assertEquals(KeyMaterial.fromJwk(io.inji.verify.issuer.TestFixtures.json(jwk)).thumbprint(), c.signingKeyThumbprint());
    }

    @Test
    void sdJwtWithoutUsableCertHasNoKeyThumbprint() throws Exception {
        String h = b64("{\"alg\":\"ES256\",\"kid\":\"did:web:issuer.example.org#key-0\",\"x5c\":[\"bm90IGEgY2VydA==\"]}");
        CredentialIssuerContext c = extractor.extract(h + "." + b64("{\"iss\":\"did:web:issuer.example.org\"}") + ".c2ln");
        assertNull(c.signingKeyThumbprint());
        assertEquals("did:web:issuer.example.org#key-0", c.signingKeyId());
    }

    @Test
    void cwtIsUnsupportedAndGarbageIsMalformed() {
        assertEquals(IssuerExtractionException.Kind.UNSUPPORTED_FORMAT,
                assertThrows(IssuerExtractionException.class, () -> extractor.extract("D28441A0A0A0")).kind());
        assertEquals(IssuerExtractionException.Kind.MALFORMED, assertThrows(IssuerExtractionException.class, () -> extractor.extract("")).kind());
        assertEquals(IssuerExtractionException.Kind.MALFORMED, assertThrows(IssuerExtractionException.class, () -> extractor.extract("{not json")).kind());
        assertEquals(IssuerExtractionException.Kind.MALFORMED, assertThrows(IssuerExtractionException.class, () -> extractor.extract("!!!.@@@.###")).kind());
        assertEquals(IssuerExtractionException.Kind.MALFORMED,
                assertThrows(IssuerExtractionException.class, () -> extractor.extract("{\"issuer\":\"a\",\"issuer\":\"b\"}")).kind(), "duplicate keys");
    }
}
