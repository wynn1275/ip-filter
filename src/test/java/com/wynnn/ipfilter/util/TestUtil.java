package com.wynnn.ipfilter.util;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.net.util.SubnetUtils;

import java.util.Arrays;
import java.util.List;

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

    public static final String IP_CLIENT_1 = "3.3.3.3";
    public static final String IP_HEADER_UNKNOWN = "UNKNOWN";
    public static final String IP_LOOPBACK = "127.0.0.1";

    public static List<SubnetUtils> createDummyDenyList() {
        IpFilterConfiguration ipFilterConfiguration = new IpFilterConfiguration();
        ipFilterConfiguration.setDeny(Arrays.asList(TEST_FILTER_DENY_LIST));
        return ipFilterConfiguration.getDeny();
    }
}
