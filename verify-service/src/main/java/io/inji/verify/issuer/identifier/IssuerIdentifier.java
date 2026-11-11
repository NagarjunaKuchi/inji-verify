package io.inji.verify.issuer.identifier;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/** Classification of the issuer identifier found in a credential. Pure syntax, no network. */
public record IssuerIdentifier(Type type, String value, String reasonCode) {

    public enum Type {
        DID_WEB, DID_JWK, HTTPS_URL,
        /** Well-formed DID using a method this deployment cannot resolve. */
        DID_UNSUPPORTED_METHOD,
        /** Well-formed identifier with a scheme we do not handle. */
        UNSUPPORTED_SCHEME,
        INVALID
    }

    private static final int MAX_LENGTH = 2048;
    private static final Pattern DID = Pattern.compile("^did:([a-z0-9]+):([A-Za-z0-9._:%~-]+)$");

    public boolean isDid() {
        return type == Type.DID_WEB || type == Type.DID_JWK;
    }

    public boolean isSupported() {
        return type == Type.DID_WEB || type == Type.DID_JWK || type == Type.HTTPS_URL;
    }

    public static IssuerIdentifier parse(String raw) {
        if (raw == null || raw.isBlank()) {
            return invalid(raw, "MISSING_ISSUER_IDENTIFIER");
        }
        String v = raw.trim();
        if (v.length() > MAX_LENGTH || hasControlOrSpace(v)) {
            return invalid(v, "INVALID_ISSUER_IDENTIFIER");
        }
        if (v.regionMatches(true, 0, "did:", 0, 4)) {
            if (v.indexOf('#') >= 0 || v.indexOf('?') >= 0 || v.indexOf('/') >= 0) {
                // An issuer must be a bare DID, not a DID URL.
                return invalid(v, "ISSUER_IDENTIFIER_NOT_BARE_DID");
            }
            var m = DID.matcher(v);
            if (!m.matches() || m.group(2).endsWith(":")) {
                return invalid(v, "INVALID_ISSUER_IDENTIFIER");
            }
            return switch (m.group(1)) {
                case "web" -> new IssuerIdentifier(Type.DID_WEB, v, null);
                case "jwk" -> new IssuerIdentifier(Type.DID_JWK, v, null);
                default -> new IssuerIdentifier(Type.DID_UNSUPPORTED_METHOD, v, "UNSUPPORTED_DID_METHOD");
            };
        }
        int colon = v.indexOf(':');
        if (colon <= 0) {
            return invalid(v, "INVALID_ISSUER_IDENTIFIER");
        }
        String scheme = v.substring(0, colon).toLowerCase(Locale.ROOT);
        if (scheme.equals("http")) {
            return invalid(v, "INSECURE_ISSUER_IDENTIFIER");
        }
        if (scheme.equals("https")) {
            try {
                URI u = new URI(v);
                if (u.getHost() == null || u.getUserInfo() != null || u.getFragment() != null) {
                    return invalid(v, "INVALID_ISSUER_IDENTIFIER");
                }
                return new IssuerIdentifier(Type.HTTPS_URL, v, null);
            } catch (Exception e) {
                return invalid(v, "INVALID_ISSUER_IDENTIFIER");
            }
        }
        if (scheme.matches("[a-z][a-z0-9+.-]*")) {
            return new IssuerIdentifier(Type.UNSUPPORTED_SCHEME, v, "UNSUPPORTED_ISSUER_IDENTIFIER");
        }
        return invalid(v, "INVALID_ISSUER_IDENTIFIER");
    }

    private static boolean hasControlOrSpace(String s) {
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c <= 0x20 || c == 0x7f) return true;
        }
        return false;
    }

    private static IssuerIdentifier invalid(String v, String reason) {
        return new IssuerIdentifier(Type.INVALID, v, reason);
    }
}
