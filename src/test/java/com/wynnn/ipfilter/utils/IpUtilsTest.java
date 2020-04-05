package com.wynnn.ipfilter.utils;

import com.wynnn.ipfilter.common.TestUtil;
import org.apache.commons.net.util.SubnetUtils;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class IpUtilsTest {

    @Test
    void test_isValidIpFormat_valid_format() {
        for (String validIp : TestUtil.TEST_VALID_IP_FORMAT) {
            assertTrue(IpUtils.isValidIpFormat(validIp));
        }
    }

    @Test
    void test_isValidIpFormat_invalid_format() {
        for (String invalidIp : TestUtil.TEST_INVALID_IP_FORMAT) {
            assertFalse(IpUtils.isValidIpFormat(invalidIp));
        }
    }

    @Test
    void test_ipToLong() {
        for (Map.Entry<Long, String> entry : TestUtil.createDummyIpPool().entrySet()) {
            assertEquals(entry.getKey(), IpUtils.ipToLong(entry.getValue()));
        }
    }

    @Test
    void test_convert_invalid_ip_then_throw() {
        assertThrows(IllegalArgumentException.class, () -> IpUtils.convert("-1"));
        assertThrows(IllegalArgumentException.class, () -> IpUtils.convert("-1", "255.255.255.255"));
    }

    @Test
    void test_convert_if_not_include_cidr_notation() {
        String testIp = "10.0.0.200";
        SubnetUtils subnet = IpUtils.convert(testIp).get();
        assertAll(
                "if ip not include cidr notation then estimate 32 bit, IP=" + testIp,
                () -> assertEquals("255.255.255.255", subnet.getInfo().getNetmask()),
                () -> assertEquals(testIp, subnet.getInfo().getAddress()),
                () -> assertEquals(testIp+"/32", subnet.getInfo().getCidrSignature()),
                () -> assertEquals(testIp, subnet.getInfo().getLowAddress()),
                () -> assertEquals(testIp, subnet.getInfo().getHighAddress())
        );
    }
}