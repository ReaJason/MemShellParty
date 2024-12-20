package com.reajason.javaweb.memshell;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.config.CommandConfig;
import com.reajason.javaweb.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.matcher.ElementMatchers;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class CommandGenerator {

    public static byte[] generate(ShellConfig config, CommandConfig shellConfig) {
        if (shellConfig.getShellClass() == null) {
            throw new IllegalArgumentException("shellConfig.getClazz() == null");
        }
        Implementation.Composable fieldSets = SuperMethodCall.INSTANCE
                .andThen(FieldAccessor.ofField("paramName").setsValue(shellConfig.getParamName()));
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(shellConfig.getShellClass())
                .name(shellConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(config.getTargetJreVersion()))
                .constructor(ElementMatchers.any()).intercept(fieldSets);

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