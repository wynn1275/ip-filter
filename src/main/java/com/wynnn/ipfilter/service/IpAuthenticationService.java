package com.wynnn.ipfilter.service;

public interface IpAuthenticationService {
    boolean hasAuth(String clientIp);
}
