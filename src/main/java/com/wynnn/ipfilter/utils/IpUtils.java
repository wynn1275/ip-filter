package com.wynnn.ipfilter.utils;

import lombok.extern.slf4j.Slf4j;

import java.util.regex.Pattern;

@Slf4j
public class IpUtils {

    public static final Pattern IP_PATTERN = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])$");
    public static final Pattern CIDR_PATTERN = Pattern.compile("^(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.){3}([01]?\\d\\d?|2[0-4]\\d|25[0-5])(/([0-9]|[1-2][0-9]|3[0-2]))?$");

    public static boolean isValidIpFormat(String ipAddress) {
        return IP_PATTERN.matcher(ipAddress).matches();
    }

    public static long ipToLong(String ipAddress) {
        long result = 0;

        String[] ipAddressInArray = ipAddress.split("\\.");
        for (int i = 3; i >= 0; i--) {
            long ip = Long.parseLong(ipAddressInArray[3 - i]);
            result |= ip << (i * 8);
        }
        log.debug("> ipToLong(ipAddress={}) decimalVal={}", ipAddress, result);
        return result;
    }

    public static long calcStartIpInSubnet(long ipLong, int cidr) {
        if (cidr == 0) {
            return 0;
        }
        if (cidr == 32) {
            return ipLong;
        }
        return ipLong & (-1 << (32 - cidr));
    }

    public static long calcEndIpInSubnet(long ipLong, int cidr) {
        if (cidr == 0) {
            return 0xffffffffL;
        }
        if (cidr == 32) {
            return ipLong;
        }
        return ipLong | ((1 << (32 - cidr)) - 1);
    }
}
