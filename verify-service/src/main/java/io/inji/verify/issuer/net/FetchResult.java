package io.inji.verify.issuer.net;

public record FetchResult(Outcome outcome, int status, byte[] body, String detail) {

    public enum Outcome { OK, NOT_FOUND, HTTP_ERROR, BLOCKED, TIMEOUT, NETWORK_ERROR, TOO_LARGE }

    public static FetchResult ok(int status, byte[] body) {
        return new FetchResult(Outcome.OK, status, body, null);
    }

    public static FetchResult of(Outcome outcome, String detail) {
        return new FetchResult(outcome, 0, null, detail);
    }

    public boolean isOk() {
        return outcome == Outcome.OK;
    }
}
