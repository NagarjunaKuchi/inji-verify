package io.inji.verify.controller;

import lombok.extern.slf4j.Slf4j;
import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.services.VCVerificationService;
import org.springframework.web.bind.annotation.*;

@RequestMapping(path = "/vc-verification")
@RestController
@Slf4j
public class VCVerificationController {
    final VCVerificationService VCVerificationService;

    public VCVerificationController(VCVerificationService vcVerificationService) {
        this.VCVerificationService = vcVerificationService;
    }

    @PostMapping()
    public VCVerificationStatusDto verify(@RequestBody String vc,
                                          @RequestParam(name = "verifyIssuer", required = false) Boolean verifyIssuer) {
        // Without the parameter the original single-argument path is used, so behaviour is unchanged.
        return verifyIssuer == null ? VCVerificationService.verify(vc) : VCVerificationService.verify(vc, verifyIssuer);
    }
}
