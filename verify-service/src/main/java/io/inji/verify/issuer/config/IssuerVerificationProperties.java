package io.inji.verify.issuer.config;

import io.inji.verify.issuer.model.CheckId;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * All issuer-verification configuration. Everything defaults to off / safe: with
 * {@code inji.verify.issuer-verification.enabled=false} (the default) no issuer-verification beans are created and
 * existing behaviour is unchanged.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "inji.verify.issuer-verification")
public class IssuerVerificationProperties {

    private boolean enabled = false;
    /** Run for every verification request unless the request sets verifyIssuer explicitly. */
    private boolean runByDefault = true;
    /** If true, a credential whose issuer is not TRUSTED gets allChecksSuccessful=false. */
    private boolean enforce = false;
    /** A, B, C (built-in presets) or the name of an entry under {@code policies}. */
    private String activePolicy = "A";
    /** Frameworks accepted by preset policy C. */
    private Set<String> approvedTrustFrameworks = new HashSet<>();
    private Duration clockSkew = Duration.ofSeconds(60);
    private Map<String, Policy> policies = new HashMap<>();
    private Did did = new Did();
    private Registry registry = new Registry();

    @Getter
    @Setter
    public static class Policy {
        private Set<CheckId> required = new HashSet<>();
        private Set<CheckId> optional = new HashSet<>();
        private Set<String> approvedTrustFrameworks = new HashSet<>();
    }

    @Getter
    @Setter
    public static class Did {
        /** Empty means any public host is allowed. Entries are exact hosts or "*.example.org". Strongly recommended in production. */
        private Set<String> allowedHosts = new HashSet<>();
        private Set<Integer> allowedPorts = new HashSet<>(Set.of(443));
        /** Only for local development. Disables the private-address SSRF block for DID resolution. */
        private boolean allowPrivateHosts = false;
        private Duration connectTimeout = Duration.ofSeconds(3);
        private Duration readTimeout = Duration.ofSeconds(5);
        private int maxResponseBytes = 65_536;
        private Duration cacheTtl = Duration.ofMinutes(5);
        private int cacheMaxEntries = 1000;
    }

    @Getter
    @Setter
    public static class Registry {
        /** none | static | rest | trqp. Additional registries can be contributed as IssuerTrustRegistry beans. */
        private String type = "none";
        private String id = "default";
        private String staticFile;
        private String restBaseUrl;
        private String restBearerToken;
        /** trqp only: the authority whose statements are queried (authority_id). Required for type=trqp. */
        private String trqpAuthorityId;
        /** trqp only: the action queried for each credential type. */
        private String trqpAction = "issue";
        /** Registries are operator-configured and often internal, so private addresses may be permitted explicitly. */
        private boolean allowPrivateHosts = false;
        private Set<Integer> allowedPorts = new HashSet<>(Set.of(443));
        private Duration connectTimeout = Duration.ofSeconds(3);
        private Duration readTimeout = Duration.ofSeconds(5);
        private int maxResponseBytes = 262_144;
        private Duration cacheTtl = Duration.ofMinutes(5);
        private Duration notFoundCacheTtl = Duration.ofMinutes(1);
        /** Reject registry records whose asOf is older than this. Zero disables the check. */
        private Duration maxMetadataAge = Duration.ZERO;
        private int cacheMaxEntries = 1000;
    }
}
