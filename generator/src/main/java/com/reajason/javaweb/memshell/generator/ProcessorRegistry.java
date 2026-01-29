package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.processors.*;
import net.bytebuddy.dynamic.DynamicType;

import java.util.Arrays;
import java.util.List;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public final class ProcessorRegistry {

    private static final List<Processor<DynamicType.Builder<?>>> BUILDER_PROCESSORS = Arrays.asList(
            new ListenerBuilderModifier(),
            new ValveBuilderModifier(),
            new DebugOffBuilderModifier()
    );

    private static final List<Processor<byte[]>> BYTE_PROCESSORS = Arrays.asList(
            new JakartaPostProcessor(),
            new JettyHandlerPostProcessor(),
            new ShrinkPostProcessor()
    );

    private ProcessorRegistry() {
        // Prevent instantiation
    }

    public static DynamicType.Builder<?> applyBuilderProcessors(
            DynamicType.Builder<?> builder,
            ShellConfig shellConfig,
            ShellToolConfig shellToolConfig) {
        for (Processor<DynamicType.Builder<?>> processor : BUILDER_PROCESSORS) {
            builder = processor.process(builder, shellConfig, shellToolConfig);
        }
        return builder;
    }

    public static byte[] applyByteProcessors(
            byte[] bytes,
            ShellConfig shellConfig,
            ShellToolConfig shellToolConfig) {
        for (Processor<byte[]> processor : BYTE_PROCESSORS) {
            bytes = processor.process(bytes, shellConfig, shellToolConfig);
        }
        return bytes;
    }
}
