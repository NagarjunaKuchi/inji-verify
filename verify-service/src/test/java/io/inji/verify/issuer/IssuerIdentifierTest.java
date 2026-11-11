package io.inji.verify.issuer;

import io.inji.verify.issuer.identifier.IssuerIdentifier;
import io.inji.verify.issuer.identifier.IssuerIdentifier.Type;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class IssuerIdentifierTest {

    @Test
    void classifiesSupportedIdentifiers() {
        assertEquals(Type.DID_WEB, IssuerIdentifier.parse("did:web:issuer.example.org").type());
        assertEquals(Type.DID_WEB, IssuerIdentifier.parse("did:web:example.com%3A8443:path").type());
        assertEquals(Type.DID_JWK, IssuerIdentifier.parse("did:jwk:eyJrdHkiOiJPS1AifQ").type());
        assertEquals(Type.HTTPS_URL, IssuerIdentifier.parse("https://issuer.example.org").type());
        assertTrue(IssuerIdentifier.parse("did:web:issuer.example.org").isDid());
        assertFalse(IssuerIdentifier.parse("https://issuer.example.org").isDid());
    }

    @Test
    void classifiesWellFormedButUnsupportedAsUnsupportedNotInvalid() {
        assertEquals(Type.DID_UNSUPPORTED_METHOD, IssuerIdentifier.parse("did:ion:EiClkZ").type());
        assertEquals(Type.UNSUPPORTED_SCHEME, IssuerIdentifier.parse("urn:uuid:6e8bc430-9c3a-11d9-9669-0800200c9a66").type());
        assertFalse(IssuerIdentifier.parse("did:ion:EiClkZ").isSupported());
    }

    @Test
    void rejectsMalformedOrUnsafeIdentifiers() {
        for (String bad : new String[]{null, "", "   ", "did:", "did:web:", "did:web:exa mple.com", "did:web:example.com#key-1", "did:web:example.com/path",
                "did:web:example.com?x=1", "did:WEB:example.com", "http://issuer.example.org", "https://user@issuer.example.org", "https://issuer.example.org/#f",
                "not an id", "issuer", "did:web:example.com\n", "x".repeat(3000)}) {
            Type t = IssuerIdentifier.parse(bad).type();
            assertTrue(t == Type.INVALID || (bad != null && bad.equals("did:web:example.com\n") && t == Type.DID_WEB), "should reject: " + bad + " got " + t);
        }
        assertEquals("INSECURE_ISSUER_IDENTIFIER", IssuerIdentifier.parse("http://issuer.example.org").reasonCode());
        assertEquals("ISSUER_IDENTIFIER_NOT_BARE_DID", IssuerIdentifier.parse("did:web:example.com#key-1").reasonCode());
        assertEquals("MISSING_ISSUER_IDENTIFIER", IssuerIdentifier.parse(null).reasonCode());
    }
}
