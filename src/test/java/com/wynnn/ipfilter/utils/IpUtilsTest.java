package com.wynnn.ipfilter.utils;

import com.wynnn.ipfilter.common.TestUtil;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
    void test_calcStartIpInSubnet() {
        for (Map.Entry<String, String[]> entry : TestUtil.createDummySubnetPool().entrySet()) {
            assertEquals(Long.parseLong(entry.getValue()[3]), IpUtils.calcStartIpInSubnet(Long.parseLong(entry.getValue()[0]), Integer.parseInt(entry.getValue()[2])));
        }
    }

    @Test
    void test_calcEndIpInSubnet() {
        for (Map.Entry<String, String[]> entry : TestUtil.createDummySubnetPool().entrySet()) {
            assertEquals(Long.parseLong(entry.getValue()[4]), IpUtils.calcEndIpInSubnet(Long.parseLong(entry.getValue()[0]), Integer.parseInt(entry.getValue()[2])));
        }
    }

    @Test
    void test_calcNumSubnet() {
        assertEquals(4294967296L, IpUtils.NUM_SUBNET[0]);
        assertEquals(2147483648L, IpUtils.NUM_SUBNET[1]);
        assertEquals(256L, IpUtils.NUM_SUBNET[24]);
        assertEquals(1, IpUtils.NUM_SUBNET[32]);
    }
}
