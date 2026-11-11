package io.inji.verify.controller;

import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.services.VCVerificationService;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class VCVerificationControllerIssuerTest {

    private static final String CT = "application/ldp+json";
    private final VCVerificationService service = Mockito.mock(VCVerificationService.class);
    private MockMvc mockMvc;

    @BeforeEach
    public void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new VCVerificationController(service)).build();
    }

    @Test
    public void withoutParamUsesOriginalPathAndOmitsIssuerField() throws Exception {
        when(service.verify("vc", CT)).thenReturn(new VCVerificationStatusDto(VerificationStatus.SUCCESS));

        mockMvc.perform(post("/vc-verification").contentType(CT).content("vc"))
                .andExpect(status().isOk())
                .andExpect(content().string("{\"verificationStatus\":\"SUCCESS\"}"));

        verify(service, times(1)).verify("vc", CT);
        verify(service, never()).verify(anyString(), anyString(), any());
    }

    @Test
    public void withParamPassesFlag() throws Exception {
        when(service.verify("vc", CT, true)).thenReturn(new VCVerificationStatusDto(VerificationStatus.SUCCESS));

        mockMvc.perform(post("/vc-verification?verifyIssuer=true").contentType(CT).content("vc"))
                .andExpect(status().isOk());

        verify(service, times(1)).verify("vc", CT, true);
    }

    @Test
    public void v2AcceptsOptionalVerifyIssuerField() throws Exception {
        mockMvc.perform(post("/v2/vc-verification").contentType("application/json")
                        .content("{\"verifiableCredential\":\"vc\",\"verifyIssuer\":true}"))
                .andExpect(status().isOk());
        verify(service, times(1)).verifyV2(argThat(r -> r != null && "vc".equals(r.getVerifiableCredential()) && Boolean.TRUE.equals(r.getVerifyIssuer())));
    }
}
