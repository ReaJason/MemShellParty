package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractShell;
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
        Class<?> shellClass = shellToolConfig.getShellClass();
        String shellClassName = shellToolConfig.getShellClassName();
        DynamicType.Builder<?> builder = build(new ByteBuddy()
                .redefine(shellClass)
                .name(shellClassName)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion())));

        String shellType = shellConfig.getShellType();
        AbstractShell shell = shellConfig.getServer().getShell();

        if (ShellType.LISTENER.equals(shellType) || ShellType.JAKARTA_LISTENER.equals(shellType)) {
            builder = ListenerGenerator.build(builder, shell.getListenerInterceptor(), shellClass, shellClassName);
        }

        if (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType)) {
            builder = ValveGenerator.build(builder, shell);
        }

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
