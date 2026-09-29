package com.reajason.javaweb.desktop.memshell.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * 应用版本：读取构建期过滤生成的 version.properties；资源缺失（如 IDE 直接运行）时回退 dev。
 */
public final class AppVersion {
    private static final String VERSION = load();

    private AppVersion() {
    }

    public static String get() {
        return VERSION;
    }

    private static String load() {
        Properties props = new Properties();
        InputStream in = AppVersion.class.getResourceAsStream("/version.properties");
        if (in != null) {
            try {
                props.load(in);
            } catch (IOException ignored) {
                // 回退 dev
            } finally {
                try {
                    in.close();
                } catch (IOException ignored) {
                    // 忽略关闭异常
                }
            }
        }
        return props.getProperty("app.version", "dev");
    }
}
