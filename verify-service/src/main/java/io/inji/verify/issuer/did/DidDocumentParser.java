package io.inji.verify.issuer.did;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.core.StreamReadConstraints;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Strict DID document parser. Rejects: duplicate JSON keys, deep nesting, documents whose id differs
 * from the DID that was resolved, oversized verification-method/relationship lists, verification
 * methods outside the document's DID and duplicate method ids.
 */
public final class DidDocumentParser {

    static final int MAX_METHODS = 32;
    static final int MAX_RELATIONSHIP_ENTRIES = 64;

    private final ObjectMapper mapper;

    public DidDocumentParser() {
        JsonFactory factory = JsonFactory.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .streamReadConstraints(StreamReadConstraints.builder().maxNestingDepth(16).maxStringLength(65_536).build())
                .build();
        this.mapper = new ObjectMapper(factory);
    }

    public DidDocument parse(byte[] json, String expectedDid) throws MalformedDidDocumentException {
        JsonNode root;
        try {
            root = mapper.readTree(json);
        } catch (Exception e) {
            throw new MalformedDidDocumentException("DID_DOCUMENT_NOT_VALID_JSON");
        }
        if (root == null || !root.isObject()) throw new MalformedDidDocumentException("DID_DOCUMENT_NOT_AN_OBJECT");
        if (!root.path("id").isTextual() || !root.get("id").asText().equals(expectedDid)) {
            throw new MalformedDidDocumentException("DID_DOCUMENT_ID_MISMATCH");
        }
        Map<String, VerificationMethod> methods = new LinkedHashMap<>();
        JsonNode vms = root.get("verificationMethod");
        if (vms != null) {
            if (!vms.isArray() || vms.size() > MAX_METHODS) throw new MalformedDidDocumentException("INVALID_VERIFICATION_METHOD_LIST");
            for (JsonNode vm : vms) addMethod(methods, vm, expectedDid);
        }
        Set<String> assertion = relationship(root.get("assertionMethod"), methods, expectedDid);
        Set<String> authentication = relationship(root.get("authentication"), methods, expectedDid);
        return new DidDocument(expectedDid, Map.copyOf(methods), Set.copyOf(assertion), Set.copyOf(authentication));
    }

    private String addMethod(Map<String, VerificationMethod> methods, JsonNode vm, String did) throws MalformedDidDocumentException {
        if (vm == null || !vm.isObject()) throw new MalformedDidDocumentException("INVALID_VERIFICATION_METHOD");
        String id = absolute(text(vm, "id"), did);
        String type = text(vm, "type");
        String controller = text(vm, "controller");
        if (id == null || type == null || controller == null) throw new MalformedDidDocumentException("INVALID_VERIFICATION_METHOD");
        if (!id.startsWith(did + "#") || id.length() == did.length() + 1) throw new MalformedDidDocumentException("VERIFICATION_METHOD_ID_OUT_OF_SCOPE");
        if (methods.containsKey(id)) throw new MalformedDidDocumentException("DUPLICATE_VERIFICATION_METHOD_ID");
        JsonNode jwk = vm.get("publicKeyJwk");
        if (jwk != null && !jwk.isObject()) throw new MalformedDidDocumentException("INVALID_VERIFICATION_METHOD");
        methods.put(id, new VerificationMethod(id, type, controller, jwk, text(vm, "publicKeyMultibase")));
        return id;
    }

    private Set<String> relationship(JsonNode node, Map<String, VerificationMethod> methods, String did) throws MalformedDidDocumentException {
        Set<String> out = new LinkedHashSet<>();
        if (node == null) return out;
        if (!node.isArray() || node.size() > MAX_RELATIONSHIP_ENTRIES) throw new MalformedDidDocumentException("INVALID_RELATIONSHIP");
        for (JsonNode item : node) {
            if (item.isTextual()) {
                String ref = absolute(item.asText(), did);
                if (ref == null) throw new MalformedDidDocumentException("INVALID_RELATIONSHIP");
                out.add(ref);
            } else if (item.isObject()) {
                if (methods.size() >= MAX_METHODS) throw new MalformedDidDocumentException("INVALID_VERIFICATION_METHOD_LIST");
                out.add(addMethod(methods, item, did));
            } else {
                throw new MalformedDidDocumentException("INVALID_RELATIONSHIP");
            }
        }
        return out;
    }

    private static String absolute(String ref, String did) {
        if (ref == null || ref.isBlank() || ref.length() > 1024) return null;
        return ref.startsWith("#") ? did + ref : ref;
    }

    private static String text(JsonNode n, String f) {
        JsonNode v = n.get(f);
        return v != null && v.isTextual() ? v.asText() : null;
    }
}
