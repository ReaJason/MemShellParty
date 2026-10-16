package com.reajason.javaweb.memshell.shelltool.neoreg;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class NeoreGeorgGenerator extends ByteBuddyShellGenerator<NeoreGeorgConfig> {
    public NeoreGeorgGenerator(ShellConfig shellConfig, NeoreGeorgConfig neoreGeorgConfig) {
        super(shellConfig, neoreGeorgConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return redefineTemplate()
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
