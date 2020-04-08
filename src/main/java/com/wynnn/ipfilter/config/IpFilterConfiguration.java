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
    private final AtomicLong numDenyIps = new AtomicLong(); // deny IP 카운터. /24 subnet 이 TreeMap 에 저장된 경우 차단하는 IP 개수는 256개로 판단.

    public void setDeny(List<String> deny) {
        numDenyIps.set(0);
        this.deny = Optional.ofNullable(deny)
                .filter(denies -> denies.size() > 0)
                .map(this::parseNestedSubnet)
                .orElse(new TreeMap<>());
        log.info("> completed to set deny={}", numDenyIps);
    }

    /**
     * 차단 IP List 를 TreeMap 으로 변환하여 저장
     * TreeMap 에 중첩된 subnet 이 포함된 경우, 중첩을 제거함
     * @param denyIps properties 파일에 등록된 차단 IP 목록
     * @return 차단하는 IP 의 subnet 정보가 담긴 TreeMap
     */
    private TreeMap<Long, Ipv4Subnet> parseNestedSubnet(List<String> denyIps) {
        TreeMap<Long, Ipv4Subnet> denyRules = new TreeMap<>();
        for (String denyIp : denyIps) {
            if (numDenyIps.get() > MAX_NUM_DENY_IP) { // MAX_NUM_DENY_IP 가 초과한 경우 더 이상 저장하지 않고 현재 TreeMap 을 return. properties 에 등록된 차단 IP 목록이 모두 저장되지 않은 경우이므로, warn log 로 저장하지 않은 시점 (현재 IP 주소)을 기록
                log.warn("> exceed max number of deny IPs (current number of applied IP is={}) : The deny applied only until the previous rule of this={}. {} not applied.",
                        numDenyIps.get(), denyIp, denyIp);
                break;
            }
            try {
                Ipv4Subnet subnet = new Ipv4Subnet(denyIp); // CIDR 표기법을 포함한 IP 주소를 읽어와, 해당 IP의 subnet 정보가 담긴 Ipv4Subnet 객체로 변환. CIDR 표기법이 아닌 경우 /32 로 인식
                Map.Entry<Long, Ipv4Subnet> floorEntry = denyRules.floorEntry(subnet.getStartIpLong());
                if (floorEntry == null) { // 첫 번째 subnet 정보인 경우
                    numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()]);
                    denyRules.put(subnet.getStartIpLong(), subnet);
                } else if (floorEntry.getValue().isNestedSubnet(subnet)) { // if new subnet is nested then skip
                    continue;
                } else {
                    // remove nested subnet
                    new HashSet<>(Optional.ofNullable(denyRules.subMap(subnet.getStartIpLong(), false, subnet.getEndIpLong(), true)) // TreeMap 에서 현재 subnet 에 중첩되는 모든 subnet 정보를 찾아 삭제
                            .map(SortedMap::entrySet)
                            .orElse(Collections.emptySet()))
                            .forEach(nested -> {
                                numDenyIps.addAndGet(-IpUtils.NUM_SUBNET[nested.getValue().getCidr()]);
                                denyRules.remove(nested.getKey());
                            });
                    if (floorEntry.getKey() == subnet.getStartIpLong()) {
                        // startIP 가 동일한 경우 subnet 정보를 replace
                        numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()] - IpUtils.NUM_SUBNET[floorEntry.getValue().getCidr()]);
                        denyRules.replace(subnet.getStartIpLong(), subnet);
                    } else {
                        // 새로운 subnet 정보인 경우 TreeMap 에 저장
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
