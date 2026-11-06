package io.inji.verify.services.impl;

import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.inji.verify.services.VCVerificationService;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.utils.Util;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class VCVerificationServiceImpl implements VCVerificationService {
    final CredentialsVerifier credentialsVerifier;

    /** Absent (null) unless inji.verify.issuer-verification.enabled=true. Field injection keeps the constructor unchanged. */
    @Autowired(required = false)
    private IssuerVerificationService issuerVerificationService;

    public VCVerificationServiceImpl(CredentialsVerifier credentialsVerifier) {
        this.credentialsVerifier = credentialsVerifier;
    }

    @Override
    public VCVerificationStatusDto verify(String vc) {
        return verify(vc, null);
    }

    @Override
    public VCVerificationStatusDto verify(String vc, Boolean verifyIssuer) {
        VerificationResult verificationResult = credentialsVerifier.verify(vc, CredentialFormat.LDP_VC);
        log.info("VC verification result:: {}", verificationResult);
        VerificationStatus status = Util.Companion.getVerificationStatus(verificationResult);

        // Issuer verification answers a different question from signature verification. Only run it for credentials
        // whose signature is valid (SUCCESS, or EXPIRED which is signature-valid), so forged input cannot trigger
        // outbound DID/registry requests.
        IssuerVerificationResult issuerVerification = null;
        boolean signatureValid = status == VerificationStatus.SUCCESS || status == VerificationStatus.EXPIRED;
        if (issuerVerificationService != null && signatureValid && issuerVerificationService.shouldVerify(verifyIssuer)) {
            issuerVerification = issuerVerificationService.verify(vc);
            if (status == VerificationStatus.SUCCESS && issuerVerificationService.isEnforcing()
                    && !issuerVerificationService.isTrusted(issuerVerification)) {
                status = VerificationStatus.INVALID;
            }
        }
        return new VCVerificationStatusDto(status, issuerVerification);
    }
}
