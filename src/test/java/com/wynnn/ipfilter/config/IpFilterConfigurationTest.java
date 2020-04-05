package com.wynnn.ipfilter.config;

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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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
                () -> assertTrue(deny.get(IpUtils.ipToLong(denyRule)).getSubnet().getInfo().getCidrSignature().endsWith("/32")));
    }

    @Test
    void test_setDeny_set_valid() {
        String denyRule = "10.10.10.11/24"; // 10.10.10.0 ~ 10.10.10.255
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.10.11/24, then denyIPs must be 10.10.10.0 ~ 10.10.10.255",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals("10.10.10.0/24", deny.firstEntry().getValue().getSubnet().getInfo().getCidrSignature()),
                () -> assertEquals("10.10.10.0", deny.firstEntry().getValue().getSubnet().getInfo().getLowAddress()),
                () -> assertEquals("10.10.10.255", deny.firstEntry().getValue().getSubnet().getInfo().getHighAddress()));
    }

    @Test
    void test_setDeny_set_valid_if_32bit() {
        String denyRule = "10.10.255.11/32"; // 10.10.255.11 only
        ipFilterConfiguration.setDeny(Collections.singletonList(denyRule));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.255.11/32, then denyIP must be 10.10.255.11 only",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals("10.10.255.11/32", deny.firstEntry().getValue().getSubnet().getInfo().getCidrSignature()),
                () -> assertEquals("10.10.255.11", deny.firstEntry().getValue().getSubnet().getInfo().getLowAddress()),
                () -> assertEquals("10.10.255.11", deny.firstEntry().getValue().getSubnet().getInfo().getHighAddress()));
    }

    @Test
    void test_setDeny_remove_nested_range_same_mask() {
        String[] denyRules = {"10.0.0.100/24", "10.0.0.200/24", "10.0.0.1/24"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rules are nested (with same cidr), then aggregate",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals("10.0.0.0/24", deny.firstEntry().getValue().getSubnet().getInfo().getCidrSignature()),
                () -> assertEquals("10.0.0.0", deny.firstEntry().getValue().getSubnet().getInfo().getLowAddress()),
                () -> assertEquals("10.0.0.255", deny.firstEntry().getValue().getSubnet().getInfo().getHighAddress()));
    }

    @Test
    void test_setDeny_remove_nested_range_different_mask() {
        String[] denyRules = {"10.0.0.100/24", "10.0.0.200/30", "10.0.0.1/26"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        TreeMap<Long, Ipv4Subnet> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rules are nested, then aggregate (even if different mask)",
                () -> assertEquals(1, deny.size()),
                () -> assertEquals("10.0.0.0/24", deny.firstEntry().getValue().getSubnet().getInfo().getCidrSignature()),
                () -> assertEquals("10.0.0.0", deny.firstEntry().getValue().getSubnet().getInfo().getLowAddress()),
                () -> assertEquals("10.0.0.255", deny.firstEntry().getValue().getSubnet().getInfo().getHighAddress()));
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
            expect.put(subnet.getIpLong(), subnet);
        }

        // then
        Stream<Executable> executables = expect.keySet().stream()
                .map(expect::get)
                .map(expectValues -> () -> assertAll(
                        String.format("test range start with %s", expectValues.getSubnet().getInfo().getAddress()),
                        () -> assertNotNull(deny.get(expectValues.getIpLong())),
                        () -> assertEquals(expectValues.getSubnet().getInfo().getCidrSignature(), deny.get(expectValues.getIpLong()).getSubnet().getInfo().getCidrSignature()),
                        () -> assertEquals(expectValues.getSubnet().getInfo().getNetmask(), deny.get(expectValues.getIpLong()).getSubnet().getInfo().getNetmask())
                ));
        assertAll("test if deny rules are nested, then aggregate (even if different mask)",
                () -> assertEquals(3, deny.size()),
                () -> assertAll(executables));
    }
}
