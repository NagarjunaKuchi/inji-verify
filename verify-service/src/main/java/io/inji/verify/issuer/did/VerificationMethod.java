package io.inji.verify.issuer.did;

import com.fasterxml.jackson.databind.JsonNode;

public record VerificationMethod(String id, String type, String controller, JsonNode publicKeyJwk, String publicKeyMultibase) {
}
