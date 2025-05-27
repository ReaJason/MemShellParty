package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.ByPassJavaModuleInterceptor;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

/**
 * @author ReaJason
 * @since 2025/5/27
 */
public abstract class ByteBuddyShellGenerator<T extends ShellToolConfig> implements ShellGenerator {
    protected final ShellConfig shellConfig;
    protected final T shellToolConfig;

    protected ByteBuddyShellGenerator(ShellConfig shellConfig, T shellToolConfig) {
        this.shellConfig = shellConfig;
        this.shellToolConfig = shellToolConfig;
    }

    protected abstract DynamicType.Builder<?> build(DynamicType.Builder<?> builder);

    @Override
    public byte[] getBytes() {
        DynamicType.Builder<?> builder = build(new ByteBuddy()
                .redefine(shellToolConfig.getShellClass())
                .name(shellToolConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion())));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        try (DynamicType.Unloaded<?> unloaded = builder.make()) {
            return ClassBytesShrink.shrink(unloaded.getBytes(), shellConfig.isShrink());
        }
    }
}
