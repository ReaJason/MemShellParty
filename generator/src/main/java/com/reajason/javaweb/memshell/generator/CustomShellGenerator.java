package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.pool.TypePool;
import org.apache.commons.lang3.StringUtils;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/3/18
 */
public class CustomShellGenerator extends ByteBuddyShellGenerator<CustomConfig> {

    public CustomShellGenerator(ShellConfig shellConfig, CustomConfig customConfig) {
        super(shellConfig, customConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        String shellClassBase64 = shellToolConfig.getShellClassBase64();
        byte[] classBytes = Base64.getDecoder().decode(shellClassBase64);
        ClassReader classReader = new ClassReader(classBytes);
        String className = classReader.getClassName().replace('/', '.');
        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(className);
        }
        ClassFileLocator classFileLocator = ClassFileLocator.Simple.of(className, classBytes);
        TypeDescription typeDescription = new TypePool.Default(
                new TypePool.CacheProvider.Simple(), classFileLocator,
                TypePool.Default.ReaderMode.FAST, TypePool.Default.ofSystemLoader()
        ).describe(className).resolve();
        shellToolConfig.setShellTypeDescription(typeDescription);
        return new ByteBuddy()
                .redefine(typeDescription, classFileLocator);
    }
}
