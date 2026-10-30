package com.reajason.javaweb.examples.plugin;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

public class ExampleShellGenerator extends ByteBuddyShellGenerator<ExampleShellToolConfig> {
    public ExampleShellGenerator(ShellConfig shellConfig, ExampleShellToolConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return redefineTemplate().field(named("value")).value(shellToolConfig.getValue());
    }
}
