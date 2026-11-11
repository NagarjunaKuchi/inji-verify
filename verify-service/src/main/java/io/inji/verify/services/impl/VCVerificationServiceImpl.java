package io.inji.verify.services.impl;

import io.inji.verify.dto.verification.SchemaAndSignatureCheckDto;
import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.dto.verification.VCVerificationRequestDto;
import io.inji.verify.dto.verification.VCVerificationResultDto;
import io.inji.verify.dto.verification.ExpiryCheckDto;
import io.inji.verify.dto.verification.StatusCheckDto;
import io.inji.verify.exception.CredentialStatusCheckException;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.inji.verify.services.VCVerificationService;
import io.inji.verify.shared.Constants;
import io.inji.verify.utils.Utils;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.CredentialStatusResult;
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import static io.inji.verify.utils.Utils.populateAllChecksSuccessful;
import static io.inji.verify.utils.Utils.populateStatusCheckDtoList;
import static io.inji.verify.utils.Utils.populateSchemaAndSignature;
import static io.inji.verify.utils.Utils.populateExpiryCheck;
import static io.inji.verify.utils.Utils.extractClaims;

@Slf4j
@Service
public class VCVerificationServiceImpl implements VCVerificationService {

    @Value("${inji.verify.claims-with-meta-data}")
    List<String> claimsWithMetaData;

    private final CredentialsVerifier credentialsVerifier;
    private final PixelPass pixelPass;

    /** Absent (null) unless inji.verify.issuer-verification.enabled=true. Field injection keeps the constructor unchanged. */
    @Autowired(required = false)
    private IssuerVerificationService issuerVerificationService;

    public VCVerificationServiceImpl(CredentialsVerifier credentialsVerifier, PixelPass pixelPass) {
        this.credentialsVerifier = credentialsVerifier;
        this.pixelPass = pixelPass;
    }

    @Override
    public VCVerificationStatusDto verify(String vc, String contentType) throws CredentialStatusCheckException {
        return verify(vc, contentType, null);
    }

    @Override
    public VCVerificationStatusDto verify(String vc, String contentType, Boolean verifyIssuer) throws CredentialStatusCheckException {
        CredentialFormat format;
        if ("application/vc+sd-jwt".equalsIgnoreCase(contentType) || "application/dc+sd-jwt".equalsIgnoreCase(contentType)) {
            format = CredentialFormat.VC_SD_JWT;
        } else if ("application/vc+cwt".equalsIgnoreCase(contentType)) {
            format = CredentialFormat.CWT_VC;
        } else {
            format = CredentialFormat.LDP_VC;
        }

        log.info("Using credential format based on Content-Type: {}", format);

        List<String> statusPurposeList = new ArrayList<>();
        statusPurposeList.add(Constants.STATUS_PURPOSE_REVOKED);
        CredentialVerificationSummary credentialVerificationSummary =
                credentialsVerifier.verifyAndGetCredentialStatus(vc, format, statusPurposeList);
        log.debug("CredentialVerificationResult: {}", credentialVerificationSummary.getVerificationResult());
        VerificationStatus status = Utils.getVcVerificationStatus(credentialVerificationSummary);

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

    @Override
    public VCVerificationResultDto verifyV2(VCVerificationRequestDto request) {
        log.debug("Processing verification request with skipStatusChecks: {}, filters: {}", request.isSkipStatusChecks(), request.getStatusCheckFilters());
        String verifiableCredential = request.getVerifiableCredential();
        CredentialFormat format = Utils.getCredentialFormat(verifiableCredential);
        VerificationResult verificationResult;
        Map<String, CredentialStatusResult> credentialStatus = null;
        ExpiryCheckDto expiryCheck = null;
        List<StatusCheckDto> statusCheck = List.of();
        Map<String, Object> claims = Map.of();

        boolean skipStatusChecks = request.isSkipStatusChecks();
            if (skipStatusChecks) {
                verificationResult = credentialsVerifier.verify(verifiableCredential, format);
            } else {
                List<String> statusCheckFilters = request.getStatusCheckFilters();
                CredentialVerificationSummary credentialVerificationSummary =
                        credentialsVerifier.verifyAndGetCredentialStatus(verifiableCredential, format, statusCheckFilters);
                verificationResult = credentialVerificationSummary.getVerificationResult();
                credentialStatus = credentialVerificationSummary.getCredentialStatus();
            }

        SchemaAndSignatureCheckDto schemaAndSignatureCheck = populateSchemaAndSignature(verificationResult);
        if (schemaAndSignatureCheck.isValid()) {
            expiryCheck = populateExpiryCheck(verificationResult);
            statusCheck = (!skipStatusChecks) ? populateStatusCheckDtoList(credentialStatus) : List.of();
            claims = request.isIncludeClaims() ? extractClaims(verifiableCredential, format, claimsWithMetaData, pixelPass) : Map.of();
        }

        boolean allChecksSuccessful = populateAllChecksSuccessful(schemaAndSignatureCheck, expiryCheck, statusCheck, null);

        // Issuer verification answers a different question from signature verification (is the issuer trusted for
        // this credential, not just was it signed). Only run for credentials whose signature is valid, so
        // forged input cannot be used to trigger outbound DID/registry requests.
        IssuerVerificationResult issuerVerification = null;
        if (issuerVerificationService != null && schemaAndSignatureCheck.isValid()
                && issuerVerificationService.shouldVerify(request.getVerifyIssuer())) {
            issuerVerification = issuerVerificationService.verify(verifiableCredential);
            if (issuerVerificationService.isEnforcing() && !issuerVerificationService.isTrusted(issuerVerification)) {
                allChecksSuccessful = false;
            }
        }

        VCVerificationResultDto result = new VCVerificationResultDto(allChecksSuccessful, schemaAndSignatureCheck, expiryCheck, statusCheck, claims);
        result.setIssuerVerification(issuerVerification);
        return result;
    }
}
