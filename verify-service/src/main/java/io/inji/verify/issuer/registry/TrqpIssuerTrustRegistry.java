package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.model.LifecycleStatus;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Adapter for registries that implement the ToIP Trust Registry Query Protocol (TRQP) v2.0 HTTPS binding,
 * such as the Affinidi trust registry. One authorization query is sent per credential type:
 * <pre>POST {baseUrl}/authorization
 *   {"authority_id": "...", "entity_id": "&lt;issuer DID&gt;", "action": "issue", "resource": "&lt;credential type&gt;"}
 *   200 {"authorized": true|false, ...}   404 RFC 7807 problem = authority has no statement about this entity</pre>
 *
 * <p>TRQP answers only "is entity X authorised for action Y on resource Z by authority A". It carries no issuer
 * name, lifecycle status, accreditation or validity, so this adapter maps it to the canonical model as follows
 * and no further:
 * <ul>
 *   <li>authorised for at least one queried type -&gt; Found, with {@code authorizedCredentialTypes} = the types answered
 *       {@code true}. Status is reported ACTIVE because the authority currently authorises the issuer; suspension or
 *       revocation can only show up as a denial. No name, accreditation or framework is invented.</li>
 *   <li>denied for every type, or 404 problem for every type -&gt; NotFound. TRQP cannot say whether the issuer is
 *       unknown, suspended or revoked, so those are not distinguished.</li>
 *   <li>any failure, timeout, malformed or mismatching answer for any type -&gt; Unavailable (never "untrusted").</li>
 * </ul>
 * Use trust policy D (or a custom policy) with this registry: policy A requires accreditation data TRQP cannot supply.
 */
public final class TrqpIssuerTrustRegistry implements IssuerTrustRegistry {

    static final int MAX_TYPES = 10;
    static final int MAX_FIELD_LENGTH = 256;

    private final String registryId;
    private final String authorityId;
    private final String action;
    private final String endpoint;
    private final HttpFetcher fetcher;
    private final ObjectMapper mapper = new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());

    public TrqpIssuerTrustRegistry(String registryId, String baseUrl, String authorityId, String action, HttpFetcher fetcher) {
        if (baseUrl == null || baseUrl.isBlank()) throw new IllegalArgumentException("TRQP base URL is required");
        if (authorityId == null || authorityId.isBlank()) throw new IllegalArgumentException("TRQP authority id is required");
        this.registryId = registryId;
        this.authorityId = authorityId;
        this.action = action == null || action.isBlank() ? "issue" : action;
        this.endpoint = (baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl) + "/authorization";
        this.fetcher = fetcher;
    }

    @Override
    public String registryId() {
        return registryId;
    }

    @Override
    public boolean credentialTypeAware() {
        return true;
    }

    /** TRQP needs the resource (credential type); without it nothing can be asked. */
    @Override
    public RegistryLookup lookup(String issuerId) {
        return new RegistryLookup.Unavailable(registryId, "CREDENTIAL_TYPE_REQUIRED");
    }

    @Override
    public RegistryLookup lookup(String issuerId, Collection<String> credentialTypes) {
        List<String> types = new ArrayList<>(new LinkedHashSet<>(credentialTypes == null ? List.<String>of() : credentialTypes));
        types.removeIf(t -> t == null || "VerifiableCredential".equals(t));
        if (types.isEmpty()) return new RegistryLookup.Unavailable(registryId, "NO_CREDENTIAL_TYPE_TO_QUERY");
        if (types.size() > MAX_TYPES) return new RegistryLookup.Unavailable(registryId, "TOO_MANY_CREDENTIAL_TYPES");

        Set<String> authorized = new LinkedHashSet<>();
        Instant evaluated = null;
        for (String type : types) {
            if (!sendable(type)) continue; // cannot be a legitimate registry resource; treated as not authorised
            Answer a = ask(issuerId, type);
            if (a.failure != null) return new RegistryLookup.Unavailable(registryId, a.failure);
            if (a.authorized) {
                authorized.add(type);
                if (a.evaluated != null && (evaluated == null || a.evaluated.isBefore(evaluated))) evaluated = a.evaluated;
            }
        }
        if (authorized.isEmpty()) return new RegistryLookup.NotFound(registryId);
        return new RegistryLookup.Found(registryId, new IssuerMetadata(issuerId, null, null, null, null, LifecycleStatus.ACTIVE,
                null, null, List.of(), Set.of(), authorized, Set.of(), evaluated));
    }

    private static boolean sendable(String value) {
        if (value.isBlank() || value.length() > MAX_FIELD_LENGTH) return false;
        for (int i = 0; i < value.length(); i++) {
            if (Character.isISOControl(value.charAt(i))) return false;
        }
        return true;
    }

    private record Answer(boolean authorized, Instant evaluated, String failure) {
        static Answer yes(Instant evaluated) {
            return new Answer(true, evaluated, null);
        }

        static Answer no() {
            return new Answer(false, null, null);
        }

        static Answer fail(String reason) {
            return new Answer(false, null, reason);
        }
    }

    private Answer ask(String issuerId, String type) {
        byte[] body;
        try {
            ObjectNode q = mapper.createObjectNode();
            q.put("authority_id", authorityId);
            q.put("entity_id", issuerId);
            q.put("action", action);
            q.put("resource", type);
            body = mapper.writeValueAsBytes(q);
        } catch (Exception e) {
            return Answer.fail("REGISTRY_REQUEST_ERROR");
        }
        FetchResult r = fetcher.post(URI.create(endpoint), body);
        switch (r.outcome()) {
            case OK:
                return parse(r.body(), issuerId, type);
            case NOT_FOUND:
                return isProblemDetails(r.body()) ? Answer.no() : Answer.fail("REGISTRY_ENDPOINT_NOT_FOUND");
            case TIMEOUT:
                return Answer.fail("REGISTRY_TIMEOUT");
            default:
                return Answer.fail("REGISTRY_UNAVAILABLE");
        }
    }

    /** A TRQP "unknown" answer is an RFC 7807 problem; a bare/HTML 404 usually means a wrong URL and is not evidence. */
    private boolean isProblemDetails(byte[] body) {
        if (body == null) return false;
        try {
            JsonNode n = mapper.readTree(body);
            return n != null && n.isObject() && n.path("type").isTextual() && n.path("title").isTextual();
        } catch (Exception e) {
            return false;
        }
    }

    private Answer parse(byte[] body, String issuerId, String type) {
        try {
            JsonNode n = mapper.readTree(body);
            if (n == null || !n.isObject() || !n.path("authorized").isBoolean()) return Answer.fail("MALFORMED_REGISTRY_RESPONSE");
            if (mismatch(n, "entity_id", issuerId) || mismatch(n, "authority_id", authorityId)
                    || mismatch(n, "resource", type) || mismatch(n, "action", action)) {
                return Answer.fail("REGISTRY_RESPONSE_MISMATCH");
            }
            if (!n.get("authorized").asBoolean()) return Answer.no();
            Instant evaluated = null;
            if (n.path("time_evaluated").isTextual()) {
                try {
                    evaluated = Instant.parse(n.get("time_evaluated").asText());
                } catch (Exception ignored) {
                    // optional; an unparsable timestamp only disables staleness protection for this answer
                }
            }
            return Answer.yes(evaluated);
        } catch (Exception e) {
            return Answer.fail("MALFORMED_REGISTRY_RESPONSE");
        }
    }

    /** The echo is optional in our reading of the spec, but if present it must match what we asked. */
    private static boolean mismatch(JsonNode n, String field, String expected) {
        JsonNode v = n.get(field);
        return v != null && !v.isNull() && !(v.isTextual() && v.asText().equals(expected));
    }
}
