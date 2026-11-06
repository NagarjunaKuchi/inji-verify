package io.inji.verify.issuer.crypto;

public class KeyException extends Exception {
    public enum Kind {
        /** Valid-looking but we do not support this encoding/curve (our limitation). */
        UNSUPPORTED,
        /** Malformed, contains private material, or cryptographically weak. */
        INVALID
    }

    private final Kind kind;
    private final String reasonCode;

    public KeyException(Kind kind, String reasonCode) {
        super(reasonCode);
        this.kind = kind;
        this.reasonCode = reasonCode;
    }

    public Kind kind() {
        return kind;
    }

    public String reasonCode() {
        return reasonCode;
    }
}
