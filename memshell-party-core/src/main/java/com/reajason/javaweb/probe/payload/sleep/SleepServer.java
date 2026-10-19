package com.reajason.javaweb.probe.payload.sleep;

/**
 * @author ReaJason
 * @since 2025/7/31
 */
public class SleepServer {

    private static String server;
    private static int seconds;
    
    public SleepServer() {
        try {
            // ServerProbe 可能返回 SpringWebMvc,Tomcat 这类框架前缀拼接的类型，用 contains 命中容器类型
            String detected = getServer();
            if (detected != null && detected.contains(server)) {
                Thread.sleep(1000L * seconds);
            }
        } catch (Throwable ignored) {
        }
    }

    private String getServer() {
        return null;
    }
}
