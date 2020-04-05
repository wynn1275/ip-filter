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
import java.util.TreeSet;

@Configuration
@ConfigurationProperties(prefix = "ip-filter")
@Getter
@Slf4j
public class IpFilterConfiguration {

    private TreeMap<Long, Ipv4Subnet> deny;

    public void setDeny(List<String> deny) {
        this.deny = Optional.ofNullable(deny)
                .filter(denies -> denies.size() > 0)
                .map(this::parseSubnet)
                .map(this::removeNestedSubnet)
                .orElse(new TreeMap<>());
        log.debug("> completed to set deny={}", this.deny);
    }

    private TreeSet<Ipv4Subnet> parseSubnet(List<String> denyIps) {
        TreeSet<Ipv4Subnet> treeSet = new TreeSet<>();
        for (String denyIp : denyIps) {
            try {
                treeSet.add(new Ipv4Subnet(denyIp));
            } catch (Exception e) {
                log.info("> cannot parse IP because invalid format, IP={}", denyIp, e);
            }
        }
        return treeSet;
    }

    private TreeMap<Long, Ipv4Subnet> removeNestedSubnet(TreeSet<Ipv4Subnet> denySubnet) {
        TreeMap<Long, Ipv4Subnet> denyRules = new TreeMap<>();
        for (Ipv4Subnet subnet : denySubnet) {
            Map.Entry<Long, Ipv4Subnet> entry = denyRules.floorEntry(subnet.getIpLong());
            if (entry == null || !entry.getValue().getSubnet().getInfo().isInRange(subnet.getSubnet().getInfo().getAddress())) {
                denyRules.put(subnet.getIpLong(), subnet);
            }
        }
        return denyRules;
    }
}
