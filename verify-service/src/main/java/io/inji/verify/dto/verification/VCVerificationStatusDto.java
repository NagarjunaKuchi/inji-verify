package io.inji.verify.dto.verification;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.Getter;

@Getter
public class VCVerificationStatusDto {
    VerificationStatus verificationStatus;

    /** Present only when issuer verification ran; omitted from the JSON otherwise so existing clients see no change. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    IssuerVerificationResult issuerVerification;

    public VCVerificationStatusDto(VerificationStatus verificationStatus) {
        this.verificationStatus = verificationStatus;
    }

    public VCVerificationStatusDto(VerificationStatus verificationStatus, IssuerVerificationResult issuerVerification) {
        this.verificationStatus = verificationStatus;
        this.issuerVerification = issuerVerification;
    }
}
