package io.inji.verify.issuer.did;

import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;

/** did:web method-specific identifier to HTTPS URL, per the did:web specification, with strict validation. */
public final class DidWebUrls {

    private static final Pattern SEGMENT = Pattern.compile("^[A-Za-z0-9._~-]{1,128}$");
    private static final Pattern HOST_PORT = Pattern.compile("^([A-Za-z0-9.-]{1,253})(?:%3[Aa]([0-9]{1,5}))?$");

    private DidWebUrls() {
    }

    /** @throws IllegalArgumentException with a stable reason code */
    public static URI toUri(String did) {
        if (did == null || !did.startsWith("did:web:")) throw new IllegalArgumentException("INVALID_ISSUER_IDENTIFIER");
        String[] parts = did.substring("did:web:".length()).split(":", -1);
        var hp = HOST_PORT.matcher(parts[0]);
        if (!hp.matches()) throw new IllegalArgumentException("INVALID_DID_WEB_HOST");
        String host = hp.group(1).toLowerCase(Locale.ROOT);
        String port = hp.group(2);
        if (port != null && (Integer.parseInt(port) < 1 || Integer.parseInt(port) > 65535)) throw new IllegalArgumentException("INVALID_DID_WEB_HOST");
        StringBuilder path = new StringBuilder();
        for (int i = 1; i < parts.length; i++) {
            String seg = parts[i];
            if (!SEGMENT.matcher(seg).matches() || seg.equals(".") || seg.equals("..")) throw new IllegalArgumentException("INVALID_DID_WEB_PATH");
            path.append('/').append(seg);
        }
        String p = parts.length == 1 ? "/.well-known/did.json" : path + "/did.json";
        return URI.create("https://" + host + (port != null ? ":" + port : "") + p);
    }
}
