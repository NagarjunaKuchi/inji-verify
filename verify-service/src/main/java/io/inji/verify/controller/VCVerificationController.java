package io.inji.verify.controller;

import io.inji.verify.dto.verification.VCVerificationRequestDto;
import io.inji.verify.dto.verification.VCVerificationResultDto;
import io.inji.verify.exception.CredentialStatusCheckException;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.services.VCVerificationService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
public class VCVerificationController {
    final VCVerificationService VCVerificationService;

    public VCVerificationController(VCVerificationService vcVerificationService) {
        this.VCVerificationService = vcVerificationService;
    }

    @PostMapping(path = "/vc-verification")
    public VCVerificationStatusDto verify(@RequestBody String vc, @RequestHeader("Content-Type") String contentType,
                                          @RequestParam(name = "verifyIssuer", required = false) Boolean verifyIssuer) throws CredentialStatusCheckException {
        // Without the parameter the original two-argument path is used, so behaviour is unchanged.
        return verifyIssuer == null ? VCVerificationService.verify(vc, contentType) : VCVerificationService.verify(vc, contentType, verifyIssuer);
    }

    @PostMapping(path = "/v2/vc-verification", consumes = MediaType.APPLICATION_JSON_VALUE)
    public VCVerificationResultDto verifyV2(@Valid @RequestBody VCVerificationRequestDto request) {
        return VCVerificationService.verifyV2(request);
    }
}