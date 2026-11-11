package io.inji.verify.issuer.crypto;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.Base64;

import static io.inji.verify.issuer.TestFixtures.*;
import static org.junit.jupiter.api.Assertions.*;

class KeyMaterialTest {

    @Test
    void matchesRfc7638RsaThumbprintVector() throws Exception {
        String jwk = "{\"kty\":\"RSA\",\"n\":\"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw\",\"e\":\"AQAB\",\"alg\":\"RS256\",\"kid\":\"2011-04-29\"}";
        assertEquals("NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", KeyMaterial.fromJwk(json(jwk)).thumbprint());
    }

    @Test
    void ed25519KeyHasSameIdentityAcrossJwkAndJcaForms() throws Exception {
        KeyPair kp = ed25519();
        assertEquals(KeyMaterial.fromJwk(json(ed25519Jwk(kp.getPublic()))).thumbprint(), KeyMaterial.fromPublicKey(kp.getPublic()).thumbprint());
    }

    @Test
    void ecKeyHasSameIdentityAcrossJwkAndJcaForms() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
        PublicKey pub = g.generateKeyPair().getPublic();
        byte[] enc = pub.getEncoded(); // SPKI ends with 0x04 || X || Y
        byte[] x = Arrays.copyOfRange(enc, enc.length - 64, enc.length - 32), y = Arrays.copyOfRange(enc, enc.length - 32, enc.length);
        Base64.Encoder b = Base64.getUrlEncoder().withoutPadding();
        String jwk = "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"" + b.encodeToString(x) + "\",\"y\":\"" + b.encodeToString(y) + "\"}";
        assertEquals(KeyMaterial.fromJwk(json(jwk)).thumbprint(), KeyMaterial.fromPublicKey((ECPublicKey) pub).thumbprint());
        assertEquals("P-256", KeyMaterial.fromPublicKey(pub).crv());
    }

    @Test
    void decodesEd25519MultibaseDidKeyExample() throws Exception {
        // Expected x value was decoded independently (Python base58 -> strip 0xed01 -> base64url), not with production code.
        KeyInfo mb = KeyMaterial.fromMultibase("z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
        KeyInfo jwk = KeyMaterial.fromJwk(json("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"Lm_M42cB3HkUiODQsXRcweM6TByfzEHGO9ND274JcOY\"}"));
        assertEquals(jwk.thumbprint(), mb.thumbprint());
    }

    @Test
    void rejectsPrivateKeyMaterialInDidDocumentKeys() {
        KeyException e = assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json(
                "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik\",\"d\":\"AAAA\"}")));
        assertEquals("PRIVATE_KEY_MATERIAL_PRESENT", e.reasonCode());
        assertEquals(KeyException.Kind.INVALID, e.kind());
    }

    @Test
    void rejectsMalformedWeakAndUnsupportedKeys() {
        // wrong coordinate length
        assertEquals("MALFORMED_JWK", assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"AAAA\"}"))).reasonCode());
        // padded base64
        assertEquals("MALFORMED_JWK", assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json("{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik=\"}"))).reasonCode());
        // weak RSA (512 bit)
        String smallN = Base64.getUrlEncoder().withoutPadding().encodeToString(new java.math.BigInteger(512, new java.util.Random(1)).setBit(511).toByteArray());
        assertEquals("WEAK_RSA_KEY", assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json("{\"kty\":\"RSA\",\"n\":\"" + smallN + "\",\"e\":\"AQAB\"}"))).reasonCode());
        // unsupported (our limitation, not malice); multibase sample below is an X25519 key (0xec01)
        KeyException unsupported = assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json("{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik\"}")));
        assertEquals(KeyException.Kind.UNSUPPORTED, unsupported.kind());
        assertEquals(KeyException.Kind.UNSUPPORTED, assertThrows(KeyException.class, () -> KeyMaterial.fromMultibase("z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc")).kind());
        assertEquals(KeyException.Kind.UNSUPPORTED, assertThrows(KeyException.class, () -> KeyMaterial.fromJwk(json("{\"kty\":\"foo\"}"))).kind());
    }
}
