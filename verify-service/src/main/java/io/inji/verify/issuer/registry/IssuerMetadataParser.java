package io.inji.verify.issuer.registry;

import com.fasterxml.jackson.databind.JsonNode;
import io.inji.verify.issuer.model.Accreditation;
import io.inji.verify.issuer.model.IssuerMetadata;
import io.inji.verify.issuer.model.LifecycleStatus;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Strict mapping of the canonical registry JSON to {@link IssuerMetadata}. Used for static files and for
 * REST registry responses so malformed or hostile data is rejected identically everywhere.
 *
 * <pre>
 * { "issuerId": "did:web:issuer.example.org", "name": "...", "legalName": "...", "organizationType": "...",
 *   "jurisdiction": "IN", "status": "ACTIVE", "validFrom": "2026-01-01", "validUntil": "2027-12-31",
 *   "accreditations": [{"id":"..","authority":"..","status":"ACTIVE","validFrom":"..","validUntil":".."}],
 *   "trustFrameworks": ["..."], "authorizedCredentialTypes": ["..."], "keyThumbprints": ["..."], "asOf": "..." }
 * </pre>
 */
public final class IssuerMetadataParser {

    private static final int MAX_ITEMS = 256;
    private static final int MAX_TEXT = 512;

    private IssuerMetadataParser() {
    }

    public static IssuerMetadata parse(JsonNode n) throws MalformedMetadataException {
        if (n == null || !n.isObject()) throw new MalformedMetadataException("not an object");
        String issuerId = requiredText(n, "issuerId");
        LifecycleStatus status;
        try {
            status = LifecycleStatus.valueOf(requiredText(n, "status"));
        } catch (IllegalArgumentException e) {
            throw new MalformedMetadataException("invalid status");
        }
        List<Accreditation> accreditations = new ArrayList<>();
        JsonNode acc = n.get("accreditations");
        if (acc != null) {
            if (!acc.isArray() || acc.size() > MAX_ITEMS) throw new MalformedMetadataException("invalid accreditations");
            for (JsonNode a : acc) {
                if (!a.isObject()) throw new MalformedMetadataException("invalid accreditation");
                LifecycleStatus as;
                try {
                    as = LifecycleStatus.valueOf(requiredText(a, "status"));
                } catch (IllegalArgumentException e) {
                    throw new MalformedMetadataException("invalid accreditation status");
                }
                accreditations.add(new Accreditation(optText(a, "id"), optText(a, "authority"), as,
                        time(a, "validFrom", false), time(a, "validUntil", true)));
            }
        }
        return new IssuerMetadata(issuerId, optText(n, "name"), optText(n, "legalName"), optText(n, "organizationType"),
                optText(n, "jurisdiction"), status, time(n, "validFrom", false), time(n, "validUntil", true), accreditations,
                strings(n, "trustFrameworks"), strings(n, "authorizedCredentialTypes"), strings(n, "keyThumbprints"),
                time(n, "asOf", false));
    }

    private static String requiredText(JsonNode n, String f) throws MalformedMetadataException {
        String v = optText(n, f);
        if (v == null || v.isBlank()) throw new MalformedMetadataException("missing " + f);
        return v;
    }

    private static String optText(JsonNode n, String f) throws MalformedMetadataException {
        JsonNode v = n.get(f);
        if (v == null || v.isNull()) return null;
        if (!v.isTextual() || v.asText().length() > MAX_TEXT) throw new MalformedMetadataException("invalid " + f);
        return v.asText();
    }

    private static Set<String> strings(JsonNode n, String f) throws MalformedMetadataException {
        JsonNode v = n.get(f);
        Set<String> out = new LinkedHashSet<>();
        if (v == null || v.isNull()) return out;
        if (!v.isArray() || v.size() > MAX_ITEMS) throw new MalformedMetadataException("invalid " + f);
        for (JsonNode i : v) {
            if (!i.isTextual() || i.asText().isBlank() || i.asText().length() > MAX_TEXT) throw new MalformedMetadataException("invalid " + f);
            out.add(i.asText());
        }
        return out;
    }

    /** Date-only values are interpreted in UTC; a date-only validUntil is inclusive of that whole day. */
    private static Instant time(JsonNode n, String f, boolean endOfDayIfDateOnly) throws MalformedMetadataException {
        String s = optText(n, f);
        if (s == null) return null;
        try {
            if (s.length() == 10) {
                LocalDate d = LocalDate.parse(s);
                return (endOfDayIfDateOnly ? d.plusDays(1) : d).atStartOfDay(ZoneOffset.UTC).toInstant();
            }
            return Instant.parse(s);
        } catch (Exception e) {
            throw new MalformedMetadataException("invalid " + f);
        }
    }
}
