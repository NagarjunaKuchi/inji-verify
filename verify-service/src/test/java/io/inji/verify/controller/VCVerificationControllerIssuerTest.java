package io.inji.verify.controller;

import io.inji.verify.dto.verification.VCVerificationStatusDto;
import io.inji.verify.services.VCVerificationService;
import io.mosip.vercred.vcverifier.data.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

public class VCVerificationControllerIssuerTest {

    private final VCVerificationService service = Mockito.mock(VCVerificationService.class);
    private MockMvc mockMvc;

    @BeforeEach
    public void setUp() {
        mockMvc = MockMvcBuilders.standaloneSetup(new VCVerificationController(service)).build();
    }

    @Test
    public void withoutParamUsesOriginalPathAndOmitsIssuerField() throws Exception {
        when(service.verify("vc")).thenReturn(new VCVerificationStatusDto(VerificationStatus.SUCCESS));

        mockMvc.perform(post("/vc-verification").contentType(MediaType.APPLICATION_JSON).content("vc"))
                .andExpect(status().isOk())
                .andExpect(content().json("{\"verificationStatus\":\"SUCCESS\"}", true));

        verify(service, times(1)).verify("vc");
        verify(service, never()).verify(anyString(), any());
    }

    @Test
    public void withParamPassesFlag() throws Exception {
        when(service.verify("vc", true)).thenReturn(new VCVerificationStatusDto(VerificationStatus.SUCCESS));

        mockMvc.perform(post("/vc-verification?verifyIssuer=true").contentType(MediaType.APPLICATION_JSON).content("vc"))
                .andExpect(status().isOk());

        verify(service, times(1)).verify("vc", true);
    }
}
