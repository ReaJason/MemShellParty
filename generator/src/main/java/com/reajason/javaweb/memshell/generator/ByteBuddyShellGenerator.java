package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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

    protected byte[] postProcessBytes(byte[] classBytes) {
        return classBytes;
    }

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

        builder = ProcessorRegistry.applyBuilderProcessors(builder, shellConfig, shellToolConfig)
                .name(shellClassName)
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()));

        try (DynamicType.Unloaded<?> unloaded = builder.make()) {
            byte[] bytes = postProcessBytes(unloaded.getBytes());
            return ProcessorRegistry.applyByteProcessors(bytes, shellConfig, shellToolConfig);
        }
    }
}
