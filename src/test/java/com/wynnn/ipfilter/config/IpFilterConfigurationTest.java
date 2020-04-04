package com.wynnn.ipfilter.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.net.util.SubnetUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.boot.context.properties.source.ConfigurationPropertySource;
import org.springframework.boot.context.properties.source.MapConfigurationPropertySource;
import org.springframework.core.io.ClassPathResource;

import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Slf4j
public class IpFilterConfigurationTest {

    private static IpFilterConfiguration ipFilterConfiguration;

    @BeforeEach
    void setUp() {
        YamlPropertiesFactoryBean factoryBean = new YamlPropertiesFactoryBean();
        factoryBean.setResources(new ClassPathResource("ip-deny-rule.yml"));

        Properties properties = factoryBean.getObject();

        ConfigurationPropertySource propertySource = new MapConfigurationPropertySource(properties);
        Binder binder = new Binder(propertySource);

        ipFilterConfiguration = binder.bind("ip-filter", IpFilterConfiguration.class).get();
    }

    @Test
    void test_loadProperty() {
        assertEquals(ipFilterConfiguration.getDeny().get(0).getInfo().getCidrSignature(), "10.0.0.0/24");
    }

    @Test
    void test_setDeny_if_invalidSubnet_then_skip() {
        String[] denyRules = {"10.0.0.0 /32", "10 .0.0.0/24", "10.256.267.289"}; // do not allow space chars in the middle of IP string
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        assertEquals(ipFilterConfiguration.getDeny().size(), 0);
    }

    @Test
    void test_setDeny_if_not_cidr_notation_then_set_32bit_mask() {
        String[] denyRules = {"10.0.0.0"};
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        List<SubnetUtils> deny = ipFilterConfiguration.getDeny();
        assertAll("if denyRule has only ipv4 and not include cidr notation, then set 32 bit mask",
                () -> assertTrue(deny.size() > 0),
                () -> assertTrue(deny.get(0).getInfo().getCidrSignature().endsWith("/32")));
    }

    @Test
    void test_setDeny_test_set_valid() {
        String[] denyRules = {"10.10.10.11/24"}; // 10.10.10.0 ~ 10.10.10.255
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        List<SubnetUtils> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.10.11/24, then denyIPs must be 10.10.10.0 ~ 10.10.10.255",
                () -> assertTrue(deny.size() > 0),
                () -> assertEquals("10.10.10.11/24", deny.get(0).getInfo().getCidrSignature()),
                () -> assertEquals("10.10.10.0", deny.get(0).getInfo().getLowAddress()),
                () -> assertEquals("10.10.10.255", deny.get(0).getInfo().getHighAddress()));
    }

    @Test
    void test_setDeny_test_set_valid_if_32bit() {
        String[] denyRules = {"10.10.255.11/32"}; // 10.10.255.11 only
        ipFilterConfiguration.setDeny(Arrays.asList(denyRules));
        List<SubnetUtils> deny = ipFilterConfiguration.getDeny();
        assertAll("test if deny rule is 10.10.255.11/32, then denyIP must be 10.10.255.11 only",
                () -> assertTrue(deny.size() > 0),
                () -> assertEquals("10.10.255.11/32", deny.get(0).getInfo().getCidrSignature()),
                () -> assertEquals("10.10.255.11", deny.get(0).getInfo().getLowAddress()),
                () -> assertEquals("10.10.255.11", deny.get(0).getInfo().getHighAddress()));
    }
}