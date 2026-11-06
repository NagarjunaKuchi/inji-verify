package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.net.FetchResult;
import io.inji.verify.issuer.net.HttpFetcher;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * Generic REST registry client. Contract (deliberately vendor-neutral; adapt other registries by
 * implementing {@link IssuerTrustRegistry} or by fronting them with a thin adapter):
 * <pre>GET {baseUrl}/issuers/{url-encoded issuerId}
 *   200 -> canonical issuer JSON (see IssuerMetadataParser), issuerId must equal the requested id
 *   404 -> issuer not registered
 *   anything else / timeout / malformed -> treated as registry unavailable (INCONCLUSIVE, never UNTRUSTED)</pre>
 */
public final class RestIssuerTrustRegistry implements IssuerTrustRegistry {

    private final String registryId;
    private final String baseUrl;
    private final HttpFetcher fetcher;
    private final ObjectMapper mapper = new ObjectMapper(JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build());

    public RestIssuerTrustRegistry(String registryId, String baseUrl, HttpFetcher fetcher) {
        this.registryId = registryId;
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        this.fetcher = fetcher;
    }

    @Override
    public String registryId() {
        return registryId;
    }

    @Override
    public RegistryLookup lookup(String issuerId) {
        URI uri = URI.create(baseUrl + "/issuers/" + URLEncoder.encode(issuerId, StandardCharsets.UTF_8));
        FetchResult r = fetcher.fetch(uri);
        switch (r.outcome()) {
            case OK:
                try {
                    JsonNode json = mapper.readTree(r.body());
                    IssuerMetadata m = IssuerMetadataParser.parse(json);
                    if (!m.issuerId().equals(issuerId)) return new RegistryLookup.Unavailable(registryId, "REGISTRY_RESPONSE_MISMATCH");
                    return new RegistryLookup.Found(registryId, m);
                } catch (Exception e) {
                    return new RegistryLookup.Unavailable(registryId, "MALFORMED_REGISTRY_RESPONSE");
                }
            case NOT_FOUND:
                return new RegistryLookup.NotFound(registryId);
            case TIMEOUT:
                return new RegistryLookup.Unavailable(registryId, "REGISTRY_TIMEOUT");
            default:
                return new RegistryLookup.Unavailable(registryId, "REGISTRY_UNAVAILABLE");
        }
    }
}
