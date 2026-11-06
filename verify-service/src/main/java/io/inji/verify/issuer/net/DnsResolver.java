package io.inji.verify.issuer.net;

import java.net.InetAddress;
import java.net.UnknownHostException;

@FunctionalInterface
public interface DnsResolver {
    InetAddress[] resolve(String host) throws UnknownHostException;

    DnsResolver SYSTEM = InetAddress::getAllByName;
}
