package io.inji.verify.issuer.policy;

import io.inji.verify.issuer.model.CheckId;
import io.inji.verify.issuer.model.CheckResult;
import io.inji.verify.issuer.model.CheckStatus;
import io.inji.verify.issuer.model.DisplayStatus;
import io.inji.verify.issuer.model.TrustStatus;

import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

/**
 * Pure function from check results to a decision. Fail-closed:
 * <ul>
 *   <li>any required FAIL, or a lifecycle hard-stop, gives UNTRUSTED (evidence beats missing data)</li>
 *   <li>otherwise any required check that is missing, INCONCLUSIVE or NOT_EVALUATED gives INCONCLUSIVE</li>
 *   <li>TRUSTED only when every required check is PASS or NOT_APPLICABLE</li>
 * </ul>
 */
public final class TrustPolicyEngine {

    private static final Set<String> HARD_STOP_REASONS = Set.of("ISSUER_REVOKED", "ISSUER_SUSPENDED", "ISSUER_DEACTIVATED");

    public TrustEvaluation evaluate(TrustPolicy policy, Map<CheckId, CheckResult> results) {
        boolean fail = false, inconclusive = false;
        Set<String> reasons = new LinkedHashSet<>();

        CheckResult active = results.get(CheckId.ISSUER_ACTIVE);
        if (active != null && active.status() == CheckStatus.FAIL && HARD_STOP_REASONS.contains(active.reasonCode())) {
            fail = true;
            reasons.add(active.reasonCode());
        }

        for (CheckId id : CheckId.values()) {
            if (!policy.isRequired(id)) continue;
            CheckResult r = results.get(id);
            CheckStatus s = r == null ? CheckStatus.NOT_EVALUATED : r.status();
            switch (s) {
                case PASS, NOT_APPLICABLE -> {
                }
                case FAIL -> {
                    fail = true;
                    reasons.add(r.reasonCode());
                }
                default -> {
                    inconclusive = true;
                    reasons.add(r == null ? "CHECK_NOT_RUN" : r.reasonCode());
                }
            }
        }

        TrustStatus status = fail ? TrustStatus.UNTRUSTED : inconclusive ? TrustStatus.INCONCLUSIVE : TrustStatus.TRUSTED;
        return new TrustEvaluation(status, display(status, results), java.util.List.copyOf(reasons));
    }

    private static DisplayStatus display(TrustStatus status, Map<CheckId, CheckResult> results) {
        if (status == TrustStatus.TRUSTED) return DisplayStatus.TRUSTED_ISSUER;
        if (status == TrustStatus.INCONCLUSIVE) return DisplayStatus.VERIFICATION_INCONCLUSIVE;
        if (reason(results, CheckId.ISSUER_ACTIVE, "ISSUER_REVOKED")) return DisplayStatus.ISSUER_REVOKED;
        if (reason(results, CheckId.ISSUER_ACTIVE, "ISSUER_SUSPENDED")) return DisplayStatus.ISSUER_SUSPENDED;
        if (reason(results, CheckId.ISSUER_REGISTERED, "ISSUER_NOT_REGISTERED") || reason(results, CheckId.DID_RESOLUTION, "DID_NOT_FOUND")) {
            return DisplayStatus.ISSUER_NOT_FOUND;
        }
        return DisplayStatus.UNTRUSTED_ISSUER;
    }

    private static boolean reason(Map<CheckId, CheckResult> results, CheckId id, String code) {
        CheckResult r = results.get(id);
        return r != null && r.status() == CheckStatus.FAIL && code.equals(r.reasonCode());
    }
}
