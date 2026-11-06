package io.inji.verify.issuer.net;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

class UrlSafetyPolicyTest {

    private static DnsResolver dns(String... ips) {
        return host -> {
            InetAddress[] out = new InetAddress[ips.length];
            for (int i = 0; i < ips.length; i++) out[i] = InetAddress.getByName(ips[i]);
            return out;
        };
    }

    private static UrlSafetyPolicy policy(String... ips) {
        return new UrlSafetyPolicy(Set.of(443), Set.of(), false, dns(ips));
    }

    private static String reason(UrlSafetyPolicy p, String url) {
        return assertThrows(UnsafeUrlException.class, () -> p.check(URI.create(url))).reasonCode();
    }

    @Test
    void allowsPublicHttpsHost() throws Exception {
        policy("93.184.216.34").check(URI.create("https://issuer.example.org/.well-known/did.json"));
    }

    @Test
    void blocksNonPublicAddressesIncludingCloudMetadata() {
        for (String ip : new String[]{"127.0.0.1", "10.1.2.3", "172.16.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
                "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "224.0.0.1", "255.255.255.255", "198.18.0.1"}) {
            assertEquals("ADDRESS_NOT_PUBLIC", reason(policy(ip), "https://issuer.example.org/did.json"), ip);
        }
    }

    @Test
    void blocksWhenAnyResolvedAddressIsPrivate() {
        assertEquals("ADDRESS_NOT_PUBLIC", reason(policy("93.184.216.34", "10.0.0.1"), "https://issuer.example.org/did.json"));
    }

    @Test
    void blocksNonHttpsSchemesUserinfoAndFragments() {
        UrlSafetyPolicy p = policy("93.184.216.34");
        assertEquals("SCHEME_NOT_ALLOWED", reason(p, "http://issuer.example.org/did.json"));
        assertEquals("SCHEME_NOT_ALLOWED", reason(p, "file:///etc/passwd"));
        assertEquals("SCHEME_NOT_ALLOWED", reason(p, "gopher://issuer.example.org/"));
        assertEquals("USERINFO_NOT_ALLOWED", reason(p, "https://user:pw@issuer.example.org/did.json"));
        assertEquals("FRAGMENT_NOT_ALLOWED", reason(p, "https://issuer.example.org/did.json#x"));
    }

    @Test
    void blocksIpLiteralsAndOddHostForms() {
        UrlSafetyPolicy p = policy("93.184.216.34");
        for (String host : new String[]{"127.0.0.1", "[::1]", "2130706433", "0x7f.0.0.1", "localhost", "metadata", "169.254.169.254"}) {
            String r = reason(p, "https://" + host + "/did.json");
            assertTrue(r.equals("HOST_NOT_ALLOWED") || r.equals("HOST_MISSING"), host + " -> " + r);
        }
    }

    @Test
    void enforcesPortAllowListAndHostAllowList() {
        assertEquals("PORT_NOT_ALLOWED", reason(policy("93.184.216.34"), "https://issuer.example.org:8443/did.json"));
        UrlSafetyPolicy strict = new UrlSafetyPolicy(Set.of(443), Set.of("trusted.example.org", "*.gov.example"), false, dns("93.184.216.34"));
        assertEquals("HOST_NOT_IN_ALLOW_LIST", reason(strict, "https://evil.example.com/did.json"));
        assertEquals("HOST_NOT_IN_ALLOW_LIST", reason(strict, "https://nottrusted.example.org/did.json"));
        assertDoesNotThrow(strict, "https://trusted.example.org/did.json");
        assertDoesNotThrow(strict, "https://a.gov.example/did.json");
    }

    private static void assertDoesNotThrow(UrlSafetyPolicy p, String url) {
        try {
            p.check(URI.create(url));
        } catch (UnsafeUrlException e) {
            fail(url + " should be allowed but: " + e.reasonCode());
        }
    }

    @Test
    void unresolvableHostIsBlocked() {
        UrlSafetyPolicy p = new UrlSafetyPolicy(Set.of(443), Set.of(), false, h -> {
            throw new UnknownHostException(h);
        });
        assertEquals("DNS_RESOLUTION_FAILED", reason(p, "https://issuer.example.org/did.json"));
    }

    @Test
    void privateAddressesCanBeExplicitlyAllowedForOperatorConfiguredRegistries() throws Exception {
        new UrlSafetyPolicy(Set.of(443), Set.of(), true, dns("10.0.0.5")).check(URI.create("https://registry.internal.example/issuers/x"));
    }
}
