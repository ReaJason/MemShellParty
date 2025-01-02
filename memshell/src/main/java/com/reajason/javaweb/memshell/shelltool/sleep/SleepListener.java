package com.reajason.javaweb.memshell.shelltool.sleep;

import javax.servlet.ServletRequestEvent;
import javax.servlet.ServletRequestListener;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class SleepListener implements ServletRequestListener {
    private static int second = 10;

    @Override
    public void requestDestroyed(ServletRequestEvent sre) {

    }

    @Override
    public void requestInitialized(ServletRequestEvent sre) {
        try {
            Thread.sleep(second * 1000);
        } catch (InterruptedException ignored) {

        }
    }
}
