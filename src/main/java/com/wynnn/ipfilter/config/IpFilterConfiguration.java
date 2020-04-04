package com.wynnn.ipfilter.config;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.net.util.SubnetUtils;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

@Configuration
@ConfigurationProperties(prefix = "ip-filter")
@Getter
@Slf4j
public class IpFilterConfiguration {

    private List<SubnetUtils> deny;

    private static final Pattern CIDR_PATTERN = Pattern.compile("(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})/(\\d{1,3})");
    private static final String SUBNET_32BIT = "255.255.255.255";

    public void setDeny(List<String> denyIps) {
        deny = new ArrayList<>();
        for (String denyIp : denyIps) {
            log.debug("> denyIpStr={}", denyIp);
            try {
                SubnetUtils validIpWithCidr = CIDR_PATTERN.matcher(denyIp).matches() ? new SubnetUtils(denyIp) : new SubnetUtils(denyIp, SUBNET_32BIT);
                validIpWithCidr.setInclusiveHostCount(true);
                deny.add(validIpWithCidr);
            } catch (IllegalArgumentException e) {
                log.info("> cannot parse IP cause invalid format, IP={}", denyIp, e);
            }
        }
    }
}
