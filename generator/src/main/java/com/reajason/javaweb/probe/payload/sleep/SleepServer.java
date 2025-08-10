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
            if (server.equals(getServer())) {
                Thread.sleep(1000L * seconds);
            }
        } catch (Throwable ignored) {
        }
    }

    private String getServer() {
        return null;
    }
}
