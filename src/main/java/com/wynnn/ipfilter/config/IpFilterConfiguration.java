package com.wynnn.ipfilter.config;

import com.wynnn.ipfilter.model.Ipv4Subnet;
import com.wynnn.ipfilter.utils.IpUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.TreeSet;
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
                .map(this::parseSubnet)
                .map(this::removeNestedSubnet)
                .orElse(new TreeMap<>());
        log.info("> completed to set deny={}", numDenyIps);
    }

    /**
     * properties 에서 subnet 을 읽어와 Ipv4Subnet 으로 변환 및 정렬 (subnet 의 시작Ip 가 빠른 순서 및 CIDR 가 큰 순서)
     *
     * @param denyIps properties 파일에 등록된 차단 IP 목록
     * @return 변환 및 정렬된 subnet 정보
     */
    private TreeSet<Ipv4Subnet> parseSubnet(List<String> denyIps) {
        TreeSet<Ipv4Subnet> subnets = new TreeSet<>();
        for (String denyIp : denyIps) {
            try {
                subnets.add(new Ipv4Subnet(denyIp));
            } catch (Exception e) {
                log.info("> exception when parse IP={}", denyIp, e);
            }
        }
        return subnets;
    }

    /**
     * 중첩된 subnet 을 제거
     *
     * @param subnets 정렬된 subnet 정보
     * @return 중첩이 제거된 subnet 정보
     */
    private TreeMap<Long, Ipv4Subnet> removeNestedSubnet(TreeSet<Ipv4Subnet> subnets) {
        TreeMap<Long, Ipv4Subnet> denyRules = new TreeMap<>();
        for (Ipv4Subnet subnet : subnets) {
            if (numDenyIps.get() > MAX_NUM_DENY_IP) { // MAX_NUM_DENY_IP 가 초과한 경우 더 이상 저장하지 않고 현재 TreeMap 을 return. 단, sorting 된 이후이므로 properties 파일에 기록된 순서가 아니니 주의
                log.warn("> exceed max number of deny IPs : The deny applied only until the previous rule of this={}. not applied {}.", numDenyIps.get(), subnet);
                break;
            }
            Map.Entry<Long, Ipv4Subnet> floorEntry = denyRules.floorEntry(subnet.getIpLong());
            if (floorEntry == null || !floorEntry.getValue().isNestedSubnet(subnet)) {
                numDenyIps.addAndGet(IpUtils.NUM_SUBNET[subnet.getCidr()]);
                denyRules.put(subnet.getStartIpLong(), subnet);
            }
        }
        return denyRules;
    }
}
