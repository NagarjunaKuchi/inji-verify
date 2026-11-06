package io.inji.verify.issuer.model;

import java.util.List;

/**
 * The only facts taken from the credential itself: who it claims to be from, what it claims to be,
 * and which key signed it. Any other issuer attribute inside the credential is deliberately ignored.
 *
 * @param signingKeyId         verification method / kid reference (DID URL) the credential points at; may be null
 * @param signingKeyThumbprint RFC 7638 thumbprint of the key proven to have signed (e.g. from x5c); may be null
 * @param proofPurpose         LDP proof purpose (expected "assertionMethod"); may be null
 */
public record CredentialIssuerContext(
        String format,
        String issuerId,
        List<String> credentialTypes,
        String signingKeyId,
        String signingKeyThumbprint,
        String proofPurpose) {

    public CredentialIssuerContext {
        credentialTypes = credentialTypes == null ? List.of() : List.copyOf(credentialTypes);
    }
}
