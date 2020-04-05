package com.wynnn.ipfilter.controller;

import com.wynnn.ipfilter.model.ResponseData;
import com.wynnn.ipfilter.service.IpAuthenticationService;
import com.wynnn.ipfilter.utils.IpUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@RequestMapping("/ipv4")
@RestController
@Slf4j
@RequiredArgsConstructor
public class IpAuthenticationController {

    private final IpAuthenticationService ipAuthService;

    @GetMapping
    public ResponseEntity<ResponseData> authenticateClientIp(HttpServletRequest request) {
        return Optional.ofNullable(getClientIp(request))
                .filter(StringUtils::isNotBlank)
                .filter(IpUtils::isValidIpFormat)
                .map(clientIp -> ipAuthService.hasAuth(clientIp)
                        ? ResponseEntity.ok(ResponseData.authorized(clientIp))
                        : ResponseEntity.ok(ResponseData.unauthorized(clientIp)))
                .orElse(ResponseEntity.badRequest().body(ResponseData.unauthorized("Invalid IP")));
    }

    private String getClientIp(HttpServletRequest request) {
        String clientIp = request.getHeader("X-Forwarded-For");
        if (StringUtils.isBlank(clientIp) || "unknown".equalsIgnoreCase(clientIp)) {
            //Proxy 서버인 경우
            clientIp = request.getHeader("Proxy-Client-IP");
        }
        if (StringUtils.isBlank(clientIp) || "unknown".equalsIgnoreCase(clientIp)) {
            //Weblogic 서버인 경우
            clientIp = request.getHeader("WL-Proxy-Client-IP");
        }
        if (StringUtils.isBlank(clientIp) || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getHeader("HTTP_CLIENT_IP");
        }
        if (StringUtils.isBlank(clientIp) || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (StringUtils.isBlank(clientIp) || "unknown".equalsIgnoreCase(clientIp)) {
            clientIp = request.getRemoteAddr();
        }
        log.debug("> getClientIp={}", clientIp);
        return clientIp;
    }
}
