package com.reajason.javaweb.probe.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.buddy.ByPassJavaModuleInterceptor;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.StaticBlockSelfConstructorCall;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.ProbeContentConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

/**
 * @author ReaJason
 * @since 2025/5/27
 */
public abstract class ByteBuddyShellGenerator<T extends ProbeContentConfig> implements ShellGenerator {
    protected final ProbeConfig probeConfig;
    protected final T probeContentConfig;

    public ByteBuddyShellGenerator(ProbeConfig probeConfig, T probeContentConfig) {
        this.probeConfig = probeConfig;
        this.probeContentConfig = probeContentConfig;
    }

    protected abstract DynamicType.Builder<?> build(ByteBuddy buddy);

    @Override
    public byte[] getBytes() {
        DynamicType.Builder<?> builder = build(new ByteBuddy());

        if (probeConfig.needByPassJavaModule()) {
            builder = ByPassJavaModuleInterceptor.extend(builder);
        }

        if (probeConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        if (probeConfig.isStaticInitialize()) {
            builder = StaticBlockSelfConstructorCall.extend(builder);
        }

        try (DynamicType.Unloaded<?> unloaded = builder.make()) {
            return ClassBytesShrink.shrink(unloaded.getBytes(), probeConfig.isShrink());
        }
    }
}
