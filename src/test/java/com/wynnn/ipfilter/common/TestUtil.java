package com.wynnn.ipfilter.common;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
import com.wynnn.ipfilter.model.Ipv4Subnet;
import lombok.extern.slf4j.Slf4j;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

@Slf4j
public class TestUtil {

    public static final String[] TEST_FILTER_DENY_LIST = {
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "1.1.1.1",
            "1.1.1.2/32",
            "1.1.1.5/31" // 1.1.1.4/32 + 1.1.1.5/32
    };

    public static final String[] TEST_EXPECT_DENY_IP = {
            "10.0.0.0",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.0",
            "172.16.31.20",
            "192.168.255.255",
            "1.1.1.1",
            "1.1.1.2",
            "1.1.1.4",
            "1.1.1.5"
    };

    public static final String[] TEST_EXPECT_ALLOW_IP = {
            "1.1.1.3",
            "127.0.0.1",
            "2.2.2.2",
            "255.255.255.255",
            "0.0.0.0"
    };

    public static final String[] TEST_VALID_IP_FORMAT = {
            "0.0.0.0",
            "1.1.1.1",
            "1.1.1.10",
            "10.10.10.1",
            "99.99.99.99",
            "100.100.123.123",
            "200.200.200.200",
            "255.255.255.255"
    };

    public static final String[] TEST_INVALID_IP_FORMAT = {
            "-1",
            "a",
            "1,1,1,1",
            "-1.0.0.0",
            "0.0.0.256",
            "1000.0.0.0",
            "1. 2.3.4",
            "1.1.1.1/24" // cidr 미포함해야 valid IP 로 판단
    };

    public static final String IP_CLIENT_1 = "3.3.3.3";
    public static final String IP_HEADER_UNKNOWN = "UNKNOWN";
    public static final String IP_LOOPBACK = "127.0.0.1";

    public static TreeMap<Long, Ipv4Subnet> createDummyDenyRule() {
        IpFilterConfiguration ipFilterConfiguration = new IpFilterConfiguration();
        ipFilterConfiguration.setDeny(Arrays.asList(TEST_FILTER_DENY_LIST));
        return ipFilterConfiguration.getDeny();
    }

    public static Map<Long, String> createDummyIpPool() {
        Map<Long, String> returnVal = new HashMap<>();
        returnVal.put(0L, "0.0.0.0");
        returnVal.put(1L, "0.0.0.1");
        returnVal.put(167772160L, "10.0.0.0");
        returnVal.put(2130706433L, "127.0.0.1");
        returnVal.put(3362022500L, "200.100.100.100");
        returnVal.put(3368576100L, "200.200.100.100");
        returnVal.put(4261412865L, "254.0.0.1");
        returnVal.put(4294904330L, "255.255.10.10");
        returnVal.put(4294967295L, "255.255.255.255");
        return returnVal;
    }

    /**
     * dummy subnet pool
     * @return  key=ip subnet string with cidr notation
     *          value=subnet info
     *          value[0]=ip address (long)
     *          value[1]=ip address string without cidr notation
     *          value[2]=cidr (number of bit)
     *          value[3]=start ip (long)
     *          value[4]=end ip (long)
     */
    public static Map<String, String[]> createDummySubnetPool() {
        Map<String, String[]> returnVal = new HashMap<>();
        returnVal.put("0.0.0.0/0", new String[]{"0", "0.0.0.0", "0", "0", "4294967295"});   // 0.0.0.0 ~ 255.255.255.255
        returnVal.put("0.0.0.0/1", new String[]{"0", "0.0.0.0", "1", "0", "2147483647"});   // 0.0.0.0 ~ 127.255.255.255
        returnVal.put("0.0.0.0/12", new String[]{"0", "0.0.0.0", "12", "0", "1048575"});    // 0.0.0.0 ~ 0.15.255.255
        returnVal.put("0.0.0.0/32", new String[]{"0", "0.0.0.0", "32", "0", "0"});          // 0.0.0.0 ~ 0.0.0.0

        returnVal.put("0.0.0.1/0", new String[]{"1", "0.0.0.1", "0", "0", "4294967295"});   // 0.0.0.0 ~ 255.255.255.255
        returnVal.put("0.0.0.1/24", new String[]{"1", "0.0.0.1", "24", "0", "255"});        // 0.0.0.0 ~ 0.0.0.255
        returnVal.put("0.0.0.1/32", new String[]{"1", "0.0.0.1", "32", "1", "1"});          // 0.0.0.1 ~ 0.0.0.1

        returnVal.put("0.50.0.3/5", new String[]{"3276803", "0.50.0.3", "5", "0", "134217727"});        // 0.0.0.0 ~ 7.255.255.255
        returnVal.put("0.50.0.3/6", new String[]{"3276803", "0.50.0.3", "6", "0", "67108863"});         // 0.0.0.0 ~ 3.255.255.255
        returnVal.put("0.50.0.3/24", new String[]{"3276803", "0.50.0.3", "24", "3276800", "3277055"});  // 0.50.0.0 ~ 0.50.0.255
        returnVal.put("0.50.0.3/32", new String[]{"3276803", "0.50.0.3", "32", "3276803", "3276803"});  // 0.50.0.3 ~ 0.50.0.3

        returnVal.put("254.0.0.1/0", new String[]{"4261412865", "254.0.0.1", "0", "0", "4294967295"});           // 0.0.0.0 ~ 255.255.255.255
        returnVal.put("254.0.0.1/12", new String[]{"4261412865", "254.0.0.1", "12", "4261412864", "4262461439"});// 254.0.0.0 ~ 254.15.255.255
        returnVal.put("254.0.0.1/20", new String[]{"4261412865", "254.0.0.1", "20", "4261412864", "4261416959"});// 254.0.0.0 ~ 254.0.15.255
        returnVal.put("254.0.0.1/32", new String[]{"4261412865", "254.0.0.1", "32", "4261412865", "4261412865"});// 254.0.0.1 ~ 254.0.0.1

        returnVal.put("255.255.255.255/0", new String[]{"4294967295", "255.255.255.255", "0", "0", "4294967295"});// 0.0.0.0 ~ 255.255.255.255
        returnVal.put("255.255.255.255/10", new String[]{"4294967295", "255.255.255.255", "10", "4290772992", "4294967295"});// 255.192.0.0 ~ 255.255.255.255
        returnVal.put("255.255.255.255/27", new String[]{"4294967295", "255.255.255.255", "27", "4294967264", "4294967295"});// 255.255.255.224 ~ 255.255.255.255
        returnVal.put("255.255.255.255/32", new String[]{"4294967295", "255.255.255.255", "32", "4294967295", "4294967295"});// 255.255.255.255 ~ 255.255.255.255
        return returnVal;
    }
}
