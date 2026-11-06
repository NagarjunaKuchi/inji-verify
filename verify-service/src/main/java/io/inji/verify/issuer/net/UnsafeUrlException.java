package io.inji.verify.issuer.net;

public class UnsafeUrlException extends Exception {
    private final String reasonCode;

    public UnsafeUrlException(String reasonCode) {
        super(reasonCode);
        this.reasonCode = reasonCode;
    }

    public String reasonCode() {
        return reasonCode;
    }
}
