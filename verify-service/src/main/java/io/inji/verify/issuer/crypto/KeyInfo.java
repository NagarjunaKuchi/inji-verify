package io.inji.verify.issuer.crypto;

/** Normalised public key identity. {@code thumbprint} is the RFC 7638 SHA-256 JWK thumbprint (base64url). */
public record KeyInfo(String kty, String crv, String thumbprint) {
}
