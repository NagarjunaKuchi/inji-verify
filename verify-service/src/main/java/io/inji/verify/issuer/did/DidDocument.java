package io.inji.verify.issuer.did;

import java.util.Map;
import java.util.Set;

/**
 * Minimal, validated view of a DID document. {@code assertionMethod} and {@code authentication}
 * contain absolute verification method ids.
 */
public record DidDocument(String id, Map<String, VerificationMethod> methods, Set<String> assertionMethod, Set<String> authentication) {
}
