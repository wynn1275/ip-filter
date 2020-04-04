package com.wynnn.ipfilter.service;

import com.wynnn.ipfilter.config.IpFilterConfiguration;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class IpAuthenticationServiceImpl implements IpAuthenticationService {

    private final IpFilterConfiguration ipFilterConfiguration;

    @Override
    public boolean hasAuth(String clientIp) {
        boolean result = ipFilterConfiguration.getDeny().stream().noneMatch(subnet -> subnet.getInfo().isInRange(clientIp));
        log.debug("> hasAuth(clientIp={}): {}", clientIp, result);
        return result;
    }
}
