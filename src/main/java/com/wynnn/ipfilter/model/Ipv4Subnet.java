package com.wynnn.ipfilter.model;

import com.wynnn.ipfilter.utils.IpUtils;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

@ToString
@Getter
@Slf4j
public class Ipv4Subnet implements Comparable<Ipv4Subnet> {
    private long startIpLong;
    private long endIpLong;
    private long ipLong;
    private int cidr;

    public Ipv4Subnet(String ipAddress) throws IllegalArgumentException {
        if (StringUtils.isBlank(ipAddress)) {
            throw new IllegalArgumentException(String.format("Cannot parse IP=%s because blank", ipAddress));
        }
        if (!IpUtils.CIDR_PATTERN.matcher(ipAddress).matches()) {
            throw new IllegalArgumentException(String.format("Cannot parse IP=%s because invalid format", ipAddress));
        }
        String[] rawIp = ipAddress.split("/");
        ipLong = IpUtils.ipToLong(rawIp[0]);
        cidr = rawIp.length == 1 ? 32 : Integer.parseInt(rawIp[1]);
        startIpLong = IpUtils.calcStartIpInSubnet(ipLong, cidr);
        endIpLong = IpUtils.calcEndIpInSubnet(ipLong, cidr);
    }

    public boolean isNestedSubnet(Ipv4Subnet other) {
        return startIpLong <= other.getStartIpLong() && other.getEndIpLong() <= endIpLong;
    }

    public boolean isInRange(long ip) {
        return startIpLong <= ip && ip <= endIpLong;
    }

    @Override
    public int compareTo(Ipv4Subnet other) {
        if (startIpLong == other.getStartIpLong()) { // if the first IPs in the subnet are the same, then sort by CIDR (in small order)
            return Integer.compare(cidr, other.getCidr());
        }
        return Long.compare(startIpLong, other.getStartIpLong()); // sort by IP (in small order)
    }
}
