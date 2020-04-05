package com.wynnn.ipfilter.utils;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.util.SubnetUtils;

import java.util.Optional;
import java.util.regex.Pattern;

@Slf4j
public class IpUtils {

    private static final Pattern IP_PATTERN = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})");
    private static final Pattern CIDR_PATTERN = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,3})");
    private static final String SUBNET_32BIT = "255.255.255.255";

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

    public static Optional<SubnetUtils> convert(String ipAddress) throws IllegalArgumentException {
        return convert(ipAddress, null);
    }

    public static Optional<SubnetUtils> convert(String ipAddress, String netmask) throws IllegalArgumentException {
        return Optional.of(ipAddress)
                .filter(StringUtils::isNoneBlank)
                .map(ip -> CIDR_PATTERN.matcher(ipAddress).matches()
                        ? new SubnetUtils(ipAddress)
                        : new SubnetUtils(ipAddress, (netmask != null ? netmask : SUBNET_32BIT)))
                .map(subnet -> {
                    subnet.setInclusiveHostCount(true);
                    return subnet;
                });
    }
}
