package io.inji.verify.services.impl;

import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.issuer.IssuerVerificationService;
import io.inji.verify.issuer.model.IssuerVerificationResult;
import io.mosip.vercred.vcverifier.CredentialsVerifier;
import io.mosip.vercred.vcverifier.constants.CredentialFormat;
import io.mosip.vercred.vcverifier.constants.CredentialValidatorConstants;
import io.mosip.vercred.vcverifier.data.VerificationResult;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Issuer-verification integration in VCVerificationServiceImpl.verify. New instance per test. */
class VCVerificationServiceImplIssuerTest {

    private CredentialsVerifier credentialsVerifier;
    private VCVerificationServiceImpl service;
    private IssuerVerificationService issuerService;
    private IssuerVerificationResult issuerResult;

    @BeforeEach
    void setUp() {
        credentialsVerifier = mock(CredentialsVerifier.class);
        service = new VCVerificationServiceImpl(credentialsVerifier);
        issuerService = mock(IssuerVerificationService.class);
        issuerResult = mock(IssuerVerificationResult.class);
        when(issuerService.verify(anyString())).thenReturn(issuerResult);
    }

    private void signature(boolean valid, String error) {
        when(credentialsVerifier.verify(anyString(), any(CredentialFormat.class))).thenReturn(new VerificationResult(valid, "", error));
    }

    @Test
    void unchangedWhenFeatureNotWired() {
        signature(true, "");
        VCVerificationStatusDto dto = service.verify("vc", true);
        assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
        assertNull(dto.getIssuerVerification());
    }

    @Test
    void attachedWhenRequested() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(true)).thenReturn(true);
        signature(true, "");
        VCVerificationStatusDto dto = service.verify("vc", true);
        assertEquals(VerificationStatus.SUCCESS, dto.getVerificationStatus());
        assertSame(issuerResult, dto.getIssuerVerification());
    }

    @Test
    void singleArgUsesServerDefault() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(null)).thenReturn(true);
        signature(true, "");
        assertSame(issuerResult, service.verify("vc").getIssuerVerification());
    }

    @Test
    void skippedWhenNotRequested() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(false)).thenReturn(false);
        signature(true, "");
        assertNull(service.verify("vc", false).getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }

    @Test
    void notRunForInvalidSignature() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(any())).thenReturn(true);
        signature(false, "");
        VCVerificationStatusDto dto = service.verify("vc", true);
        assertEquals(VerificationStatus.INVALID, dto.getVerificationStatus());
        assertNull(dto.getIssuerVerification());
        verify(issuerService, never()).verify(anyString());
    }

    @Test
    void runsForExpiredButDoesNotChangeExpiredStatus() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(true);
        when(issuerService.isTrusted(issuerResult)).thenReturn(false);
        signature(true, CredentialValidatorConstants.ERROR_CODE_VC_EXPIRED);
        VCVerificationStatusDto dto = service.verify("vc", true);
        assertEquals(VerificationStatus.EXPIRED, dto.getVerificationStatus());
        assertSame(issuerResult, dto.getIssuerVerification());
    }

    @Test
    void enforcingMakesUntrustedIssuerInvalid() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(true);
        when(issuerService.isTrusted(issuerResult)).thenReturn(false);
        signature(true, "");
        assertEquals(VerificationStatus.INVALID, service.verify("vc", true).getVerificationStatus());
    }

    @Test
    void nonEnforcingKeepsSuccess() {
        ReflectionTestUtils.setField(service, "issuerVerificationService", issuerService);
        when(issuerService.shouldVerify(true)).thenReturn(true);
        when(issuerService.isEnforcing()).thenReturn(false);
        signature(true, "");
        assertEquals(VerificationStatus.SUCCESS, service.verify("vc", true).getVerificationStatus());
    }
}
