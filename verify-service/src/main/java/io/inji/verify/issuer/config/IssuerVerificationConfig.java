package io.inji.verify.issuer.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.did.CachingDidResolver;
import io.inji.verify.issuer.did.DidDocumentParser;
import io.inji.verify.issuer.did.DidJwkResolver;
import io.inji.verify.issuer.did.DidResolution;
import io.inji.verify.issuer.did.DidResolver;
import io.inji.verify.issuer.did.DidResolvers;
import io.inji.verify.issuer.did.DidWebResolver;
import io.inji.verify.issuer.engine.IssuerVerificationEngine;
import io.inji.verify.issuer.extract.CredentialIssuerExtractor;
import io.inji.verify.issuer.metadata.IssuerMetadataService;
import io.inji.verify.issuer.metadata.TtlCache;
import io.inji.verify.issuer.net.DnsResolver;
import io.inji.verify.issuer.net.HttpFetcher;
import io.inji.verify.issuer.net.JdkHttpTransport;
import io.inji.verify.issuer.net.SafeHttpFetcher;
import io.inji.verify.issuer.net.UrlSafetyPolicy;
import io.inji.verify.issuer.policy.TrustPolicy;
import io.inji.verify.issuer.policy.TrustPolicyEngine;
import io.inji.verify.issuer.registry.IssuerTrustRegistry;
import io.inji.verify.issuer.registry.RegistryLookup;
import io.inji.verify.issuer.registry.RestIssuerTrustRegistry;
import io.inji.verify.issuer.registry.StaticIssuerTrustRegistry;
import io.inji.verify.issuer.registry.TrqpIssuerTrustRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Wires issuer verification. Only active when {@code inji.verify.issuer-verification.enabled=true}.
 * Extra {@link IssuerTrustRegistry} and {@link DidResolver} beans declared by a deployment are picked up
 * automatically, which is the extension point for enterprise registries and additional DID methods.
 */
@Configuration
@EnableConfigurationProperties(IssuerVerificationProperties.class)
@ConditionalOnProperty(prefix = "inji.verify.issuer-verification", name = "enabled", havingValue = "true")
public class IssuerVerificationConfig {

    @Bean
    public IssuerVerificationService issuerVerificationService(IssuerVerificationProperties props,
                                                               ObjectMapper objectMapper,
                                                               ObjectProvider<IssuerTrustRegistry> extraRegistries,
                                                               ObjectProvider<DidResolver> extraDidResolvers) throws Exception {
        Clock clock = Clock.systemUTC();
        IssuerVerificationProperties.Did didProps = props.getDid();

        // --- DID resolution ---
        HttpFetcher didFetcher = new SafeHttpFetcher(
                new UrlSafetyPolicy(didProps.getAllowedPorts(), didProps.getAllowedHosts(), didProps.isAllowPrivateHosts(), DnsResolver.SYSTEM),
                new JdkHttpTransport(didProps.getConnectTimeout(), didProps.getReadTimeout()),
                didProps.getMaxResponseBytes(), Map.of());
        TtlCache<String, DidResolution> didCache = new TtlCache<>(didProps.getCacheMaxEntries(), clock);
        List<DidResolver> didResolvers = new ArrayList<>();
        didResolvers.add(new CachingDidResolver(new DidWebResolver(didFetcher, new DidDocumentParser()), didCache, didProps.getCacheTtl()));
        didResolvers.add(new DidJwkResolver());
        extraDidResolvers.orderedStream().forEach(didResolvers::add);

        // --- Trust registries ---
        IssuerVerificationProperties.Registry regProps = props.getRegistry();
        List<IssuerTrustRegistry> registries = new ArrayList<>();
        switch (regProps.getType().toLowerCase()) {
            case "none":
                break;
            case "static":
                registries.add(StaticIssuerTrustRegistry.fromFile(Path.of(regProps.getStaticFile()), objectMapper));
                break;
            case "rest":
            case "trqp": {
                Map<String, String> headers = regProps.getRestBearerToken() == null || regProps.getRestBearerToken().isBlank()
                        ? Map.of() : Map.of("Authorization", "Bearer " + regProps.getRestBearerToken());
                HttpFetcher fetcher = new SafeHttpFetcher(
                        new UrlSafetyPolicy(regProps.getAllowedPorts(), java.util.Set.of(), regProps.isAllowPrivateHosts(), DnsResolver.SYSTEM),
                        new JdkHttpTransport(regProps.getConnectTimeout(), regProps.getReadTimeout()),
                        regProps.getMaxResponseBytes(), headers);
                if (regProps.getType().equalsIgnoreCase("trqp")) {
                    registries.add(new TrqpIssuerTrustRegistry(regProps.getId(), regProps.getRestBaseUrl(),
                            regProps.getTrqpAuthorityId(), regProps.getTrqpAction(), fetcher));
                } else {
                    registries.add(new RestIssuerTrustRegistry(regProps.getId(), regProps.getRestBaseUrl(), fetcher));
                }
                break;
            }
            default:
                throw new IllegalStateException("Unsupported inji.verify.issuer-verification.registry.type: " + regProps.getType());
        }
        extraRegistries.orderedStream().forEach(registries::add);

        IssuerMetadataService metadataService = new IssuerMetadataService(registries,
                new TtlCache<String, RegistryLookup>(regProps.getCacheMaxEntries(), clock),
                regProps.getCacheTtl(), regProps.getNotFoundCacheTtl(), regProps.getMaxMetadataAge(), clock);

        // --- Policy + engine ---
        IssuerVerificationEngine engine = new IssuerVerificationEngine(new DidResolvers(didResolvers), metadataService,
                new TrustPolicyEngine(), resolvePolicy(props), clock, props.getClockSkew());

        return new IssuerVerificationService(new CredentialIssuerExtractor(), engine, props.isRunByDefault(), props.isEnforce());
    }

    static TrustPolicy resolvePolicy(IssuerVerificationProperties props) {
        String name = props.getActivePolicy();
        IssuerVerificationProperties.Policy custom = props.getPolicies().get(name);
        if (custom != null) {
            if (custom.getRequired().isEmpty()) {
                throw new IllegalStateException("Trust policy '" + name + "' must declare required checks");
            }
            return new TrustPolicy(name, custom.getRequired(), custom.getOptional(), custom.getApprovedTrustFrameworks());
        }
        return switch (name) {
            case "A" -> TrustPolicy.registryStrict();
            case "B" -> TrustPolicy.cryptographicOnly();
            case "C" -> TrustPolicy.trustFramework(props.getApprovedTrustFrameworks());
            case "D" -> TrustPolicy.authorizationOnly();
            default -> throw new IllegalStateException("Unknown trust policy: " + name);
        };
    }
}
