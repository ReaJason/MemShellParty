package com.reajason.javaweb.memshell.shelltool.suo5;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/2/12
 */
public class Suo5Generator extends ByteBuddyShellGenerator<Suo5Config> {

    public Suo5Generator(ShellConfig shellConfig, Suo5Config suo5Config) {
        super(shellConfig, suo5Config);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return redefineTemplate()
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
