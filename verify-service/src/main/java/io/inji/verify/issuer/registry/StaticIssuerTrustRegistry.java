package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.model.IssuerMetadata;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

/**
 * Operator-managed registry backed by a JSON file: {@code {"registryId": "...", "issuers": [ ...canonical records... ]}}.
 * Loaded once at start-up (restart or redeploy to change). A malformed file fails start-up rather than
 * silently yielding an empty (fail-open or fail-closed by accident) registry.
 */
public final class StaticIssuerTrustRegistry implements IssuerTrustRegistry {

    private final String registryId;
    private final Map<String, IssuerMetadata> issuers = new HashMap<>();

    public StaticIssuerTrustRegistry(String registryId, Collection<IssuerMetadata> entries) {
        this.registryId = registryId;
        entries.forEach(e -> issuers.put(e.issuerId(), e));
    }

    public static StaticIssuerTrustRegistry fromFile(Path file, ObjectMapper mapper) throws IOException, MalformedMetadataException {
        try (InputStream in = Files.newInputStream(file)) {
            return fromJson(mapper.readTree(in), file.getFileName().toString(), mapper);
        }
    }

    public static StaticIssuerTrustRegistry fromJson(JsonNode root, String defaultId, ObjectMapper mapper) throws MalformedMetadataException {
        if (root == null || !root.isObject() || !root.path("issuers").isArray()) throw new MalformedMetadataException("static registry must contain an issuers array");
        String id = root.path("registryId").isTextual() ? root.get("registryId").asText() : defaultId;
        var list = new java.util.ArrayList<IssuerMetadata>();
        for (JsonNode n : root.get("issuers")) list.add(IssuerMetadataParser.parse(n));
        return new StaticIssuerTrustRegistry(id, list);
    }

    @Override
    public String registryId() {
        return registryId;
    }

    @Override
    public RegistryLookup lookup(String issuerId) {
        IssuerMetadata m = issuers.get(issuerId);
        return m == null ? new RegistryLookup.NotFound(registryId) : new RegistryLookup.Found(registryId, m);
    }
}
