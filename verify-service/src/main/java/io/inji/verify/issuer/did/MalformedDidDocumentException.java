package io.inji.verify.issuer.did;

public class MalformedDidDocumentException extends Exception {
    private final String reasonCode;

    public MalformedDidDocumentException(String reasonCode) {
        super(reasonCode);
        this.reasonCode = reasonCode;
    }

    public String reasonCode() {
        return reasonCode;
    }
}
