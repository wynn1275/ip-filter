package com.wynnn.ipfilter.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@AllArgsConstructor
@Data
public class ResponseData {
    private String resultMessage;
    private String clientIp;

    public static ResponseData authorized(String clientIp) {
        return new ResponseData("Allow", clientIp);
    }

    public static ResponseData unauthorized(String clientIp) {
        return new ResponseData("Deny", clientIp);
    }
}
