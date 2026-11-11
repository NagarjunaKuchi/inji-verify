package io.inji.verify.issuer.policy;

import io.inji.verify.issuer.model.DisplayStatus;
import io.inji.verify.issuer.model.TrustStatus;

import java.util.List;

public record TrustEvaluation(TrustStatus status, DisplayStatus displayStatus, List<String> failureReasons) {
}
