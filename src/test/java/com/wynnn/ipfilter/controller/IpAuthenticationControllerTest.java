package com.wynnn.ipfilter.controller;

import com.wynnn.ipfilter.service.IpAuthenticationService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static com.wynnn.ipfilter.common.TestUtil.IP_CLIENT_1;
import static com.wynnn.ipfilter.common.TestUtil.IP_HEADER_UNKNOWN;
import static com.wynnn.ipfilter.common.TestUtil.IP_LOOPBACK;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class IpAuthenticationControllerTest {

    @MockBean
    private IpAuthenticationService ipAuthService;

    @Autowired
    private MockMvc mockMvc;

    @Test
    void test_authenticateClientIp_blankHeaderValue() throws Exception {
        given(ipAuthService.hasAuth(anyString())).willReturn(true);
        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4"))
                .andDo(print())
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").exists())
                .andExpect(jsonPath("$.clientIp").value(IP_LOOPBACK));
    }

    @Test
    void test_authenticateClientIp_has_x_forwarded_for_header() throws Exception {
        given(ipAuthService.hasAuth(anyString())).willReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header("X-Forwarded-For", IP_CLIENT_1))
                .andDo(print())
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").exists())
                .andExpect(jsonPath("$.clientIp").value(IP_CLIENT_1));

        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header("X-Forwarded-For", "")) // blank case
                .andDo(print())
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").exists())
                .andExpect(jsonPath("$.clientIp").value(IP_LOOPBACK));

        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header("X-Forwarded-For", IP_HEADER_UNKNOWN))
                .andDo(print())
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").exists())
                .andExpect(jsonPath("$.clientIp").value(IP_LOOPBACK));
    }

    @Test
    void test_authenticateClientIp_has_other_header() throws Exception {
        final String[] otherHeaderNames = {"Proxy-Client-IP", "WL-Proxy-Client-IP", "HTTP_CLIENT_IP", "HTTP_X_FORWARDED_FOR"};
        given(ipAuthService.hasAuth(anyString())).willReturn(true);

        for (String clientIpHeaderName : otherHeaderNames) {
            mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header(clientIpHeaderName, IP_CLIENT_1))
                    .andDo(print())
                    .andExpect(status().is(HttpStatus.OK.value()))
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                    .andExpect(jsonPath("$.resultMessage").exists())
                    .andExpect(jsonPath("$.clientIp").value(IP_CLIENT_1));

            mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header(clientIpHeaderName, "")) // blank case
                    .andDo(print())
                    .andExpect(status().is(HttpStatus.OK.value()))
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                    .andExpect(jsonPath("$.resultMessage").exists())
                    .andExpect(jsonPath("$.clientIp").value(IP_LOOPBACK));

            mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header(clientIpHeaderName, IP_HEADER_UNKNOWN))
                    .andDo(print())
                    .andExpect(status().is(HttpStatus.OK.value()))
                    .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                    .andExpect(jsonPath("$.resultMessage").exists())
                    .andExpect(jsonPath("$.clientIp").value(IP_LOOPBACK));
        }
    }

    @Test
    void test_authenticateClientIp_if_allow() throws Exception {
        given(ipAuthService.hasAuth(anyString())).willReturn(true);

        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header("X-Forwarded-For", IP_CLIENT_1))
                .andDo(print())
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").value("Allow"))
                .andExpect(jsonPath("$.clientIp").value(IP_CLIENT_1));
    }

    @Test
    void test_authenticateClientIp_if_deny() throws Exception {
        given(ipAuthService.hasAuth(anyString())).willReturn(false);

        mockMvc.perform(MockMvcRequestBuilders.get("/ipv4").header("X-Forwarded-For", IP_CLIENT_1))
                .andDo(print())
                .andExpect(status().is(HttpStatus.FORBIDDEN.value()))
                .andExpect(content().contentType(MediaType.APPLICATION_JSON_VALUE))
                .andExpect(jsonPath("$.resultMessage").value("Deny"))
                .andExpect(jsonPath("$.clientIp").value(IP_CLIENT_1));
    }
}
