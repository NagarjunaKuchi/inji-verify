package io.inji.verify.issuer.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * SSRF guard applied to every outbound issuer-verification request.
 * <ul>
 *   <li>https only, no userinfo, no fragment, no IP-literal hosts</li>
 *   <li>port allow-list (default 443)</li>
 *   <li>optional host allow-list (exact or {@code *.suffix})</li>
 *   <li>every resolved address must be public (unless {@code allowPrivateAddresses}, intended for
 *       operator-configured internal registries only)</li>
 * </ul>
 * Residual risk: DNS can change between this check and the connection (rebinding). Production deployments
 * should set a host allow-list and/or an egress firewall; see docs.
 */
public final class UrlSafetyPolicy {

    private static final Pattern HOST = Pattern.compile(
            "^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$");

    private final Set<Integer> allowedPorts;
    private final Set<String> allowedHosts;
    private final boolean allowPrivateAddresses;
    private final DnsResolver dns;

    public UrlSafetyPolicy(Set<Integer> allowedPorts, Set<String> allowedHosts, boolean allowPrivateAddresses, DnsResolver dns) {
        this.allowedPorts = allowedPorts == null || allowedPorts.isEmpty() ? Set.of(443) : Set.copyOf(allowedPorts);
        this.allowedHosts = allowedHosts == null ? Set.of() : allowedHosts.stream().map(h -> h.toLowerCase(Locale.ROOT)).collect(java.util.stream.Collectors.toUnmodifiableSet());
        this.allowPrivateAddresses = allowPrivateAddresses;
        this.dns = dns == null ? DnsResolver.SYSTEM : dns;
    }

    public void check(URI uri) throws UnsafeUrlException {
        if (uri == null || uri.getScheme() == null || !uri.getScheme().equalsIgnoreCase("https")) {
            throw new UnsafeUrlException("SCHEME_NOT_ALLOWED");
        }
        if (uri.getRawUserInfo() != null) throw new UnsafeUrlException("USERINFO_NOT_ALLOWED");
        if (uri.getRawFragment() != null) throw new UnsafeUrlException("FRAGMENT_NOT_ALLOWED");
        String host = uri.getHost();
        if (host == null || host.isEmpty()) throw new UnsafeUrlException("HOST_MISSING");
        host = host.toLowerCase(Locale.ROOT);
        if (!HOST.matcher(host).matches()) throw new UnsafeUrlException("HOST_NOT_ALLOWED");
        int port = uri.getPort() == -1 ? 443 : uri.getPort();
        if (!allowedPorts.contains(port)) throw new UnsafeUrlException("PORT_NOT_ALLOWED");
        if (!allowedHosts.isEmpty() && !hostAllowed(host)) throw new UnsafeUrlException("HOST_NOT_IN_ALLOW_LIST");

        InetAddress[] addresses;
        try {
            addresses = dns.resolve(host);
        } catch (UnknownHostException e) {
            throw new UnsafeUrlException("DNS_RESOLUTION_FAILED");
        }
        if (addresses == null || addresses.length == 0) throw new UnsafeUrlException("DNS_RESOLUTION_FAILED");
        if (!allowPrivateAddresses) {
            for (InetAddress a : addresses) {
                if (isNonPublic(a)) throw new UnsafeUrlException("ADDRESS_NOT_PUBLIC");
            }
        }
    }

    private boolean hostAllowed(String host) {
        for (String entry : allowedHosts) {
            if (entry.startsWith("*.")) {
                if (host.endsWith(entry.substring(1))) return true;
            } else if (host.equals(entry)) {
                return true;
            }
        }
        return false;
    }

    /** True for loopback, any-local, link-local (incl. cloud metadata), private, CGNAT, multicast, reserved ranges. */
    public static boolean isNonPublic(InetAddress a) {
        if (a.isAnyLocalAddress() || a.isLoopbackAddress() || a.isLinkLocalAddress()
                || a.isSiteLocalAddress() || a.isMulticastAddress()) {
            return true;
        }
        byte[] b = a.getAddress();
        if (a instanceof Inet4Address) {
            return nonPublicV4(b);
        }
        if (a instanceof Inet6Address) {
            int b0 = b[0] & 0xff;
            if ((b0 & 0xfe) == 0xfc) return true;                       // fc00::/7 unique local
            if (b0 == 0x20 && (b[1] & 0xff) == 0x01 && b[2] == 0x0d && (b[3] & 0xff) == 0xb8) return true; // 2001:db8::/32 docs
            if (b0 == 0x00 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0
                    && b[8] == 0 && b[9] == 0 && (b[10] & 0xff) == 0xff && (b[11] & 0xff) == 0xff) { // ::ffff:a.b.c.d
                return nonPublicV4(new byte[]{b[12], b[13], b[14], b[15]});
            }
            if (b0 == 0x00 && b[1] == 0x64 && (b[2] & 0xff) == 0xff && (b[3] & 0xff) == 0x9b) { // 64:ff9b::/96 NAT64
                return nonPublicV4(new byte[]{b[12], b[13], b[14], b[15]});
            }
        }
        return false;
    }

    private static boolean nonPublicV4(byte[] b) {
        int o1 = b[0] & 0xff, o2 = b[1] & 0xff, o3 = b[2] & 0xff;
        if (o1 == 0 || o1 == 10 || o1 == 127) return true;
        if (o1 == 100 && o2 >= 64 && o2 <= 127) return true;             // 100.64/10 CGNAT
        if (o1 == 169 && o2 == 254) return true;                          // link-local / metadata
        if (o1 == 172 && o2 >= 16 && o2 <= 31) return true;
        if (o1 == 192 && o2 == 0 && o3 == 0) return true;                 // 192.0.0.0/24
        if (o1 == 192 && o2 == 0 && o3 == 2) return true;                 // TEST-NET-1
        if (o1 == 192 && o2 == 168) return true;
        if (o1 == 198 && (o2 == 18 || o2 == 19)) return true;             // benchmarking
        if (o1 == 198 && o2 == 51 && o3 == 100) return true;              // TEST-NET-2
        if (o1 == 203 && o2 == 0 && o3 == 113) return true;               // TEST-NET-3
        return o1 >= 224;                                                 // multicast + reserved + broadcast
    }
}
