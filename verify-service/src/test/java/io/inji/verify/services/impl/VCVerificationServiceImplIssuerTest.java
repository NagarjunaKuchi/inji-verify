package io.inji.verify.services.impl;

import io.inji.verify.dto.verification.VCVerificationRequestDto;
import io.inji.verify.dto.verification.VCVerificationResultDto;
import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.exception.CredentialStatusCheckException;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.mosip.pixelpass.PixelPass;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.data.CredentialVerificationSummary;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Issuer-verification integration in VCVerificationServiceImpl (legacy verify and verifyV2). New instance per test. */
class VCVerificationServiceImplIssuerTest {

    private static final String LDP = "application/ldp+json";
    private static final String VC = "{\"credentialSubject\":{},\"type\":[\"VerifiableCredential\"],\"proof\":{}}";

    private CredentialsVerifier credentialsVerifier;
    private VCVerificationServiceImpl service;
    private IssuerVerificationService issuerService;
    private IssuerVerificationResult issuerResult;

    @BeforeEach
    void setUp() {
        credentialsVerifier = mock(CredentialsVerifier.class);
        service = new VCVerificationServiceImpl(credentialsVerifier, mock(PixelPass.class));
        ReflectionTestUtils.setField(service, "claimsWithMetaData", List.of());
        issuerService = mock(IssuerVerificationService.class);
        issuerResult = mock(IssuerVerificationResult.class);
        when(issuerService.verify(anyString())).thenReturn(issuerResult);
    }

    private void wire() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
    }

    /** Signature valid + not expired => SUCCESS. */
    private void signature(boolean valid, String message, String errorCode) {
        VerificationResult result = new VerificationResult(valid, message, errorCode);
        CredentialVerificationSummary summary = mock(CredentialVerificationSummary.class);
        when(summary.getVerificationResult()).thenReturn(result);
        try {
            when(credentialsVerifier.verifyAndGetCredentialStatus(anyString(), any(CredentialFormat.class), anyList())).thenReturn(summary);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        when(credentialsVerifier.verify(anyString(), any(CredentialFormat.class))).thenReturn(result);
    }

    // ---- legacy /vc-verification ----

    @Test
    void legacy_unchangedWhenFeatureNotWired() throws CredentialStatusCheckException {
        signature(true, "", "");
        VCVerificationStatusDto dto = service.verify(VC, LDP, true);
        assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
        assertNull(dto.getIssuerVerification());
    }

    @Test
    void legacy_attachedWhenRequested() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        signature(true, "", "");
        VCVerificationStatusDto dto = service.verify(VC, LDP, true);
        assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
        assertSame(issuerResult, dto.getIssuerVerification());
    }

    @Test
    void legacy_twoArgUsesServerDefault() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(null)).thenReturn(true);
        signature(true, "", "");
        assertSame(issuerResult, service.verify(VC, LDP).getIssuerVerification());
    }

    @Test
    void legacy_skippedWhenNotRequested() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(false)).thenReturn(false);
        signature(true, "", "");
        assertNull(service.verify(VC, LDP, false).getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }

    @Test
    void legacy_notRunForInvalidSignature() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(any())).thenReturn(true);
        signature(false, "bad", "ERR_SIGNATURE_VERIFICATION_FAILED");
        VCVerificationStatusDto dto = service.verify(VC, LDP, true);
        assertEquals(VerificationStatus.INVALID, dto.getVerificationStatus());
        assertNull(dto.getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }

    @Test
    void legacy_runsForExpiredButKeepsExpiredStatus() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(true);
        when(issuerService.isTrusted(issuerResult)).thenReturn(false);
        signature(true, "EXPIRED", "ERR_VC_EXPIRED");
        VCVerificationStatusDto dto = service.verify(VC, LDP, true);
        assertEquals(VerificationStatus.EXPIRED, dto.getVerificationStatus());
        assertSame(issuerResult, dto.getIssuerVerification());
    }

    @Test
    void legacy_enforcingMakesUntrustedIssuerInvalid() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(true);
        when(issuerService.isTrusted(issuerResult)).thenReturn(false);
        signature(true, "", "");
        assertEquals(VerificationStatus.INVALID, service.verify(VC, LDP, true).getVerificationStatus());
    }

    @Test
    void legacy_nonEnforcingKeepsSuccess() throws CredentialStatusCheckException {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(false);
        signature(true, "", "");
        assertEquals(VerificationStatus.SUCCESS, service.verify(VC, LDP, true).getVerificationStatus());
    }

    // ---- /v2/vc-verification ----

    private VCVerificationRequestDto request(Boolean verifyIssuer) {
        return new VCVerificationRequestDto(VC, verifyIssuer);
    }

    @Test
    void v2_unchangedWhenFeatureNotWired() {
        signature(true, "", "");
        VCVerificationResultDto dto = service.verifyV2(request(true));
        assertTrue(dto.isAllChecksSuccessful());
        assertNull(dto.getIssuerVerification());
    }

    @Test
    void v2_attachedWhenRequestedAndAdvisoryByDefault() {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(false);
        signature(true, "", "");
        VCVerificationResultDto dto = service.verifyV2(request(true));
        assertSame(issuerResult, dto.getIssuerVerification());
        assertTrue(dto.isAllChecksSuccessful());
    }

    @Test
    void v2_enforcingUntrustedFailsAllChecks() {
        wire();
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(true);
        when(issuerService.isTrusted(issuerResult)).thenReturn(false);
        signature(true, "", "");
        VCVerificationResultDto dto = service.verifyV2(request(true));
        assertFalse(dto.isAllChecksSuccessful());
        assertSame(issuerResult, dto.getIssuerVerification());
    }

    @Test
    void v2_notRunForInvalidSignature() {
        wire();
        when(issuerService.shouldVerify(any())).thenReturn(true);
        signature(false, "bad", "ERR_SIGNATURE_VERIFICATION_FAILED");
        VCVerificationResultDto dto = service.verifyV2(request(true));
        assertFalse(dto.isAllChecksSuccessful());
        assertNull(dto.getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }

    @Test
    void v2_requestWithoutFlagUsesServerDefault() {
        wire();
        when(issuerService.shouldVerify(null)).thenReturn(false);
        signature(true, "", "");
        assertNull(service.verifyV2(new VCVerificationRequestDto(VC)).getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }
}
