package com.reajason.javaweb.probe.payload;

import net.bytebuddy.asm.Advice;

/**
 * @author ReaJason
 * @since 2025/7/26
 */
public class OsProbe {
    @Advice.OnMethodExit
    public static String exit(@Advice.Return(readOnly = false) String ret) {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.startsWith("win")) {
            return ret = "win";
        }
        if (os.startsWith("mac")) {
            return ret = "mac";
        }
        return ret = "linux";
    }

    @Override
    public String toString() {
        return OsProbe.exit(super.toString());
    }
}
