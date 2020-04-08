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

    /**
     * CIDR 표기법을 포함한 IP 주소를 읽어와, 해당 IP의 subnet 정보가 담긴 Ipv4Subnet 으로 변환. CIDR 표기법이 아닌 경우 /32 로 인식
     * @param ipAddress IP address with CIDR notation
     * @throws IllegalArgumentException IP 주소 형식이 아닌 경우 exception 발생
     */
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
