package com.wynnn.ipfilter.service;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
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
        long clientIpLong = IpUtils.ipToLong(clientIp);
        boolean result = Optional.ofNullable(ipFilterConfiguration.getDeny().floorEntry(clientIpLong))
                .map(Map.Entry::getValue)
                .map(subnet -> !subnet.isInRange(clientIpLong))
                .orElse(true);
        log.debug("> hasAuth(clientIp={}): {}", clientIp, result);
        return result;
    }
}
