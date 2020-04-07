package com.wynnn.ipfilter.config;

import com.wynnn.ipfilter.model.Ipv4Subnet;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

@Configuration
@ConfigurationProperties(prefix = "ip-filter")
@Getter
@Slf4j
public class IpFilterConfiguration {

    private TreeMap<Long, Ipv4Subnet> deny;

    public void setDeny(List<String> deny) {
        this.deny = Optional.ofNullable(deny)
                .filter(denies -> denies.size() > 0)
                .map(this::parseNestedSubnet)
                .orElse(new TreeMap<>());
        log.info("> completed to set deny={}", this.deny.size());
    }

    private TreeMap<Long, Ipv4Subnet> parseNestedSubnet(List<String> denyIps) {
        TreeMap<Long, Ipv4Subnet> denyRules = new TreeMap<>();
        for (String denyIp : denyIps) {
            try {
                Ipv4Subnet subnet = new Ipv4Subnet(denyIp);
                Map.Entry<Long, Ipv4Subnet> floorEntry = denyRules.floorEntry(subnet.getStartIpLong());
                if (floorEntry == null) {
                    denyRules.put(subnet.getStartIpLong(), subnet);
                } else if (floorEntry.getValue().isNestedSubnet(subnet)) { // if new subnet is nested then skip
                    continue;
                } else {
                    if (floorEntry.getKey() == subnet.getStartIpLong()) {
                        denyRules.replace(subnet.getStartIpLong(), subnet);
                    } else {
                        denyRules.put(subnet.getStartIpLong(), subnet);
                    }
                }
            } catch (Exception e) {
                log.info("> exception when parse IP={}", denyIp, e);
            }
        }
        return denyRules;
    }
}
