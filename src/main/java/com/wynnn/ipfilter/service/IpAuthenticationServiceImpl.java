package com.wynnn.ipfilter.service;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
import com.wynnn.ipfilter.model.Ipv4Subnet;
import com.wynnn.ipfilter.utils.IpUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class IpAuthenticationServiceImpl implements IpAuthenticationService {

    private final IpFilterConfiguration ipFilterConfiguration;

    @Override
    public boolean hasAuth(String clientIp) {
        boolean result = Optional.ofNullable(ipFilterConfiguration.getDeny().floorEntry(IpUtils.ipToLong(clientIp)))
                .map(Map.Entry::getValue)
                .map(Ipv4Subnet::getSubnet)
                .map(subnet -> !subnet.getInfo().isInRange(clientIp))
                .orElse(true);
        log.debug("> hasAuth(clientIp={}): {}", clientIp, result);
        return result;
    }
}
