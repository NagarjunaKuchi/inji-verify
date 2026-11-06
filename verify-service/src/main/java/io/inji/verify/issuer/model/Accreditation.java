package io.inji.verify.issuer.model;

import java.time.Instant;

public record Accreditation(String id, String authority, LifecycleStatus status, Instant validFrom, Instant validUntil) {
}
