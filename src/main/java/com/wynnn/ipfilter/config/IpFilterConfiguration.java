package com.wynnn.ipfilter.config;

import com.wynnn.ipfilter.model.Ipv4Subnet;
import com.wynnn.ipfilter.utils.IpUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.atomic.AtomicLong;

@Configuration
@ConfigurationProperties(prefix = "ip-filter")
@Getter
@Slf4j
public class IpFilterConfiguration {

    private TreeMap<Long, Ipv4Subnet> deny;
    private final int MAX_NUM_DENY_IP = 30000000; // max number of deny IPs. (30 million)
    private final AtomicLong numDenyIps = new AtomicLong();

    public void setDeny(List<String> deny) {
        numDenyIps.set(0);
        this.deny = Optional.ofNullable(deny)
                .filter(denies -> denies.size() > 0)
                .map(this::parseNestedSubnet)
                .orElse(new TreeMap<>());
        log.info("> completed to set deny={}", numDenyIps);
    }

    private TreeMap<Long, Ipv4Subnet> parseNestedSubnet(List<String> denyIps) {
        TreeMap<Long, Ipv4Subnet> denyRules = new TreeMap<>();
        for (String denyIp : denyIps) {
            if (numDenyIps.get() > MAX_NUM_DENY_IP) {
                log.warn("> exceed max number of deny IPs (current number of applied IP is={}) : The deny applied only until the previous rule of this={}. {} not applied.",
                        numDenyIps.get(), denyIp, denyIp);
                break;
            }
            try {
                Ipv4Subnet subnet = new Ipv4Subnet(denyIp);
                Map.Entry<Long, Ipv4Subnet> floorEntry = denyRules.floorEntry(subnet.getStartIpLong());
                if (floorEntry == null) {
                    numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()]);
                    denyRules.put(subnet.getStartIpLong(), subnet);
                } else if (floorEntry.getValue().isNestedSubnet(subnet)) { // if new subnet is nested then skip
                    continue;
                } else {
                    // remove nested subnet
                    new HashSet<>(Optional.ofNullable(denyRules.subMap(subnet.getStartIpLong(), false, subnet.getEndIpLong(), true))
                            .map(SortedMap::entrySet)
                            .orElse(Collections.emptySet()))
                            .forEach(nested -> {
                                numDenyIps.addAndGet(-IpUtils.NUM_SUBNET[nested.getValue().getCidr()]);
                                denyRules.remove(nested.getKey());
                            });
                    if (floorEntry.getKey() == subnet.getStartIpLong()) {
                        numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()] - IpUtils.NUM_SUBNET[floorEntry.getValue().getCidr()]);
                        denyRules.replace(subnet.getStartIpLong(), subnet);
                    } else {
                        numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()]);
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
