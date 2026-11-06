package io.inji.verify.issuer.did;

/** Result of resolving an issuer DID. Distinguishes "does not exist" from "could not reach". */
public sealed interface DidResolution {
    record Resolved(DidDocument document) implements DidResolution {
    }

    /** Document retrieved but failed validation. */
    record Malformed(String reasonCode) implements DidResolution {
    }

    record NotFound() implements DidResolution {
    }

    /** Our own safety policy refused the endpoint (SSRF guard, redirect, ...). */
    record Blocked(String reasonCode) implements DidResolution {
    }

    /** Timeout, network error, 5xx. Says nothing about the issuer. */
    record Unavailable(String reasonCode) implements DidResolution {
    }

    record Unsupported(String reasonCode) implements DidResolution {
    }
}
