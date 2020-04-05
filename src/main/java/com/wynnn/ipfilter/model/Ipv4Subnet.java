package com.wynnn.ipfilter.model;

import com.wynnn.ipfilter.utils.IpUtils;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.net.util.SubnetUtils;

@Getter
@Slf4j
public class Ipv4Subnet implements Comparable<Ipv4Subnet> {
    private long ipLong;
    private int cidr;
    private SubnetUtils subnet;

    public Ipv4Subnet(String ipAddress) throws IllegalArgumentException {
        try {
            IpUtils.convert(ipAddress)
                    .flatMap(subnet -> IpUtils.convert(subnet.getInfo().getLowAddress(), subnet.getInfo().getNetmask()))
                    .ifPresent(subnetWithFirstIp -> {
                        subnet = subnetWithFirstIp;
                        setIpLong(subnetWithFirstIp.getInfo().getAddress());
                        setCidr(subnetWithFirstIp.getInfo().getCidrSignature());
                    });
        } catch (IllegalArgumentException e) {
            log.debug("> cannot parse IP because invalid format, IP={}", ipAddress, e);
            throw e;
        }
    }

    private void setIpLong(String ipAddress) {
        ipLong = IpUtils.ipToLong(ipAddress);
    }

    private void setCidr(String ipAddrWithCidrNotation) {
        String[] cidrStr = ipAddrWithCidrNotation.split("/");
        cidr = Integer.parseInt(cidrStr[cidrStr.length - 1]);
    }

    @Override
    public int compareTo(Ipv4Subnet other) {
        if (ipLong == other.getIpLong()) { // if the first IPs in the subnet are the same, then sort by CIDR (in small order)
            return Integer.compare(cidr, other.getCidr());
        }
        return Long.compare(ipLong, other.getIpLong()); // sort by IP (in small order)
    }

    public String toString() {
        return "Ipv4Subnet(ipLong=" + this.getIpLong() + ", cidr=" + this.getCidr() + ", subnet=" + this.getSubnet().getInfo().getCidrSignature() + ")";
    }
}
