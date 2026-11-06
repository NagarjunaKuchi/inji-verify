package io.inji.verify.issuer.extract;

public class IssuerExtractionException extends Exception {
    public enum Kind { UNSUPPORTED_FORMAT, MALFORMED }

    private final Kind kind;

    public IssuerExtractionException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }
}
