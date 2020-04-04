package com.wynnn.ipfilter.service;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
import com.wynnn.ipfilter.util.TestUtil;
import org.apache.commons.net.util.SubnetUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.Executable;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class IpAuthenticationServiceImplTest {

    @Mock
    private IpFilterConfiguration ipFilterConfiguration;

    @InjectMocks
    private IpAuthenticationServiceImpl ipAuthenticationService;

    private final List<SubnetUtils> DENY_RULES = TestUtil.createDummyDenyList();

    @BeforeEach
    void setUp() {
        given(ipFilterConfiguration.getDeny()).willReturn(DENY_RULES);
    }

    @Test
    void test_hasAuth_filter_deny() {
        Stream<Executable> executables = Stream.of(TestUtil.TEST_EXPECT_DENY_IP)
                .map(denyIp -> () -> assertFalse(ipAuthenticationService.hasAuth(denyIp)));
        assertAll(executables);
    }

    @Test
    void test_hasAuth_filter_allow() {
        Stream<Executable> executables = Stream.of(TestUtil.TEST_EXPECT_ALLOW_IP)
                .map(allowIp -> () -> assertTrue(ipAuthenticationService.hasAuth(allowIp)));
        assertAll(executables);
    }
}
