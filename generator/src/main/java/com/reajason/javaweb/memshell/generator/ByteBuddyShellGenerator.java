package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.ServerFactory;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import net.bytebuddy.description.type.TypeDescription;
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

    protected abstract DynamicType.Builder<?> getBuilder();

    @Override
    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        String shellClassName = shellToolConfig.getShellClassName();
        Class<?> shellClass = shellToolConfig.getShellClass();
        if (shellClass != null) {
            shellToolConfig.setShellTypeDescription(TypeDescription.ForLoadedType.of(shellClass));
        }
        if (shellToolConfig.getShellTypeDescription() == null) {
            throw new GenerationException("shellClass or shellTypeDescription could not be null.");
        }

        String shellType = shellConfig.getShellType();
        AbstractServer server = ServerFactory.getServer(shellConfig.getServer());

        if (ShellType.LISTENER.equals(shellType) || ShellType.JAKARTA_LISTENER.equals(shellType)) {
            builder = ListenerGenerator.build(builder, server.getListenerInterceptor(), shellToolConfig.getShellTypeDescription(), shellClassName);
        }

        if (ShellType.VALVE.equals(shellType) || ShellType.JAKARTA_VALVE.equals(shellType)) {
            builder = ValveGenerator.build(builder, server, shellConfig.getServerVersion());
        }

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        builder = builder
                .name(shellClassName)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        try (DynamicType.Unloaded<?> unloaded = builder.make()) {
            return ClassBytesShrink.shrink(unloaded.getBytes(), shellConfig.isShrink());
        }
    }
}
