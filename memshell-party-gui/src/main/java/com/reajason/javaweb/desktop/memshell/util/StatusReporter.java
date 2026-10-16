package com.reajason.javaweb.desktop.memshell.util;

/**
 * 页面向窗口报告状态时携带严重级别，避免后台页面用无上下文字符串覆盖当前页面。
 */
@FunctionalInterface
public interface StatusReporter {

    enum Level {
        INFO,
        BUSY,
        SUCCESS,
        ERROR
    }

    void report(String message, Level level);
}
