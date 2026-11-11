package io.inji.verify.dto.verification;

import io.inji.verify.dto.result.VerificationRequestDto;
import jakarta.validation.constraints.NotNull;
import lombok.Getter;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@Getter
public class VCVerificationRequestDto extends VerificationRequestDto {
    @NotNull
    private String verifiableCredential;

    /**
     * Optional. When issuer verification is enabled on the server, true/false overrides the server default
     * for this request; null (absent) uses the server default.
     */
    private Boolean verifyIssuer;

    public VCVerificationRequestDto(String verifiableCredential) {
        this.verifiableCredential = verifiableCredential;
    }

    public VCVerificationRequestDto(String verifiableCredential, Boolean verifyIssuer) {
        this.verifiableCredential = verifiableCredential;
        this.verifyIssuer = verifyIssuer;
    }
}
