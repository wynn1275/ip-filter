package com.wynnn.ipfilter.service;

import org.springframework.stereotype.Service;

@Service
public class IpAuthenticationServiceImpl implements IpAuthenticationService {
    @Override
    public boolean hasAuth(String clientIp) {
        // TODO: impl
        return false;
    }
}
