package com.wynnn.ipfilter.config;

import com.wynnn.ipfilter.common.TestUtil;
import com.wynnn.ipfilter.model.Ipv4Subnet;
import com.wynnn.ipfilter.utils.IpUtils;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.core.io.ClassPathResource;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.TreeMap;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

@Slf4j
public class IpFilterConfigurationTest {

    private static IpFilterConfiguration ipFilterConfiguration;

    @BeforeAll
    static void setUp() {
        YamlPropertiesFactoryBean factoryBean = new YamlPropertiesFactoryBean();
        factoryBean.setResources(new ClassPathResource("ip-deny-rule.yml"));

        Properties properties = factoryBean.getObject();

        ConfigurationPropertySource propertySource = new MapConfigurationPropertySource(properties);
        Binder binder = new Binder(propertySource);

        ipFilterConfiguration = binder.bind("ip-filter", IpFilterConfiguration.class).get();
    }

    @Test
    void test_setDeny_load() {
        ipFilterConfiguration.setDeny(Arrays.asList(TestUtil.TEST_FILTER_DENY_LIST));
        log.debug("> denyRules={}", ipFilterConfiguration.getDeny());
        assertEquals(6, ipFilterConfiguration.getDeny().size());
    }


    @Test
    void test_setDeny_if_invalidSubnet_then_skip() {
        String[] denyRules = {"10.0.0.0 /32", "10 .0.0.0/24", "10.256.267.289"}; // do not allow space chars in the middle of IP string
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        assertEquals(0, ipFilterConfiguration.getDeny().size());
    }

    @Test
    void test_setDeny_if_not_cidr_notation_then_set_32bit_mask() {
        String denyRule = "10.0.0.0";
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("if denyRule has only ipv4 and not include cidr notation, then set 32 bit mask",
                () -> assertEquals(1, deny.size()),
                () -> assertNotNull(deny.get(IpUtils.ipToLong(denyRule))),
                () -> assertEquals(32, deny.get(IpUtils.ipToLong(denyRule)).getCidr()));
    }

    @Test
    void test_setDeny_set_valid() {
        String denyRule = "10.10.10.11/24"; // 10.10.10.0 ~ 10.10.10.255
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.10.11/24, then denyIPs must be 10.10.10.0 ~ 10.10.10.255",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(24, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("10.10.10.11"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.10.10.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.10.10.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_set_valid_if_ip_is_all() {
        String denyRule = "0.0.0.0/0"; // 0.0.0.0 ~ 255.255.255.255
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 0.0.0.0/0 then denyIPs must be 0.0.0.0 ~ 255.255.255.255",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(0, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("0.0.0.0"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("0.0.0.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("255.255.255.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_set_valid_if_ip_is_start() {
        String denyRule = "0.0.0.1/24"; // 0.0.0.0 ~ 0.0.0.255
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 0.0.0.0/24 then denyIPs must be 0.0.0.0 ~ 0.0.0.255",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(24, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("0.0.0.1"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("0.0.0.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("0.0.0.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_set_valid_if_ip_is_end() {
        String denyRule = "255.255.255.255/24"; // 255.255.255.0 ~ 0.0.0.255
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 255.255.255.255/24 then denyIPs must be 255.255.255.0 ~ 255.255.255.255",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(24, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("255.255.255.255"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("255.255.255.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("255.255.255.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_set_valid_if_32bit() {
        String denyRule = "10.10.255.11/32"; // 10.10.255.11 only
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.255.11/32, then denyIP must be 10.10.255.11 only",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(32, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("10.10.255.11"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.10.255.11"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.10.255.11"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_remove_nested_range_same_mask() {
        String[] denyRules = {"10.0.0.100/24", "10.0.0.200/24", "10.0.0.1/24"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rules are nested (with same cidr), then aggregate",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(24, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.100"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_remove_nested_range_different_mask() {
        String[] denyRules = {"10.0.0.100/24", "10.0.0.200/30", "10.0.0.1/26"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rules are nested, then aggregate (even if different mask)",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(24, deny.firstEntry().getValue().getCidr()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.100"), deny.firstEntry().getValue().getIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.0"), deny.firstEntry().getValue().getStartIpLong()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.255"), deny.firstEntry().getValue().getEndIpLong()));
    }

    @Test
    void test_setDeny_multi_range() {
        // actual deny ranges are below
        // 1.0.0.8 ~ 1.0.0.11
        // 1.0.1.2 ~ 1.0.1.3
        // 1.0.20.0 ~ 1.0.20.7
        String[] denyRules = {"1.0.0.10/30", "1.0.1.2/31", "1.0.1.3/31", "1.0.20.3/30", "1.0.20.1/29"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();

        // when
        String[] expectDenyRanges = {"1.0.0.8/30", "1.0.1.2/31", "1.0.20.0/29"};
        Map<Long, Ipv4Subnet> expect = new HashMap<>();
        for (String expectDenyRange : expectDenyRanges) {
            Ipv4Subnet subnet = new Ipv4Subnet(expectDenyRange);
            expect.put(subnet.getStartIpLong(), subnet);
        }

        // then
        Stream<Executable> executables = expect.keySet().stream()
                .map(expect::get)
                .map(expectValues -> () -> assertAll(
                        String.format("test range start with %s", expectValues.getIpLong()),
                        () -> assertNotNull(deny.get(expectValues.getStartIpLong())),
                        () -> assertEquals(expectValues.getCidr(), deny.get(expectValues.getStartIpLong()).getCidr()),
                        () -> assertEquals(expectValues.getStartIpLong(), deny.get(expectValues.getStartIpLong()).getStartIpLong()),
                        () -> assertEquals(expectValues.getEndIpLong(), deny.get(expectValues.getStartIpLong()).getEndIpLong())
                ));
        assertAll("test if deny rules are nested, then aggregate (even if different mask)",
                () -> assertEquals(3, deny.size()),
                () -> assertAll(executables));
    }

    @Test
    void test_setDeny_if_exceed_max_count_then_stop_to_set() {
        String[] denyRules = {"10.0.0.0/8", "11.0.0.0/8", "12.0.0.0/8", "13.0.0.0/8"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if exceed max count of deny IPs (30 million) then stop to set",
                () -> assertEquals(2, deny.size()),
                () -> assertEquals(IpUtils.ipToLong("11.0.0.0"), deny.lastEntry().getKey()));
    }

    @Test
    void test_setDeny_if_nested() {
        String[] denyRules = {"10.0.0.1/32", "10.0.0.2/32", "10.0.0.3/32", "10.0.0.4/8"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        log.debug(">>>>>>>>> {}", deny);
        assertAll("test if exceed max count of deny IPs (30 million) then stop to set",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals(IpUtils.ipToLong("10.0.0.0"), deny.lastEntry().getKey()));
    }
}
