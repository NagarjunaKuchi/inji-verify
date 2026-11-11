package io.inji.verify.dto.verification;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import java.util.List;
import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
public class VCVerificationResultDto {
    private boolean allChecksSuccessful;
    private SchemaAndSignatureCheckDto schemaAndSignatureCheck;
    private ExpiryCheckDto expiryCheck;
    private List<StatusCheckDto> statusCheck;
    private Map<String, Object> claims;
    /** Present only when issuer verification ran. Absent otherwise, so existing clients see no change. */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private IssuerVerificationResult issuerVerification;

    public VCVerificationResultDto(boolean allChecksSuccessful, SchemaAndSignatureCheckDto schemaAndSignatureCheck,
                                   ExpiryCheckDto expiryCheck, List<StatusCheckDto> statusCheck, Map<String, Object> claims) {
        this.allChecksSuccessful = allChecksSuccessful;
        this.schemaAndSignatureCheck = schemaAndSignatureCheck;
        this.expiryCheck = expiryCheck;
        this.statusCheck = statusCheck;
        this.claims = claims;
    }
}
