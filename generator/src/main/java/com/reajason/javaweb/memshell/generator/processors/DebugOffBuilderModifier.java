package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;
import net.bytebuddy.dynamic.DynamicType;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class DebugOffBuilderModifier implements Processor<DynamicType.Builder<?>> {

    @Override
    public DynamicType.Builder<?> process(DynamicType.Builder<?> builder, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }
        return builder;
    }
}
