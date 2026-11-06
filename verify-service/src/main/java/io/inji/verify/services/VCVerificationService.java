package io.inji.verify.services;

import io.inji.verify.dto.verification.VCVerificationStatusDto;

public interface VCVerificationService {

    VCVerificationStatusDto verify(String vc);

    /**
     * @param verifyIssuer explicit request to run issuer verification; null means use the server default.
     *                     Ignored when the issuer-verification feature is disabled.
     */
    VCVerificationStatusDto verify(String vc, Boolean verifyIssuer);
}
