package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/28
 */
public class AgentGenerator {

    private final ShellConfig config;
    private final InjectorConfig injectorConfig;

    public AgentGenerator(ShellConfig config, InjectorConfig injectorConfig) {
        this.config = config;
        this.injectorConfig = injectorConfig;
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(injectorConfig.getInjectorClass())
                .name(injectorConfig.getInjectorClassName())
                .visit(new TargetJreVersionVisitorWrapper(config.getTargetJreVersion()))
                .method(named("getAdvisorName")).intercept(FixedValue.value(injectorConfig.getShellClassName()));

        if (config.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}
