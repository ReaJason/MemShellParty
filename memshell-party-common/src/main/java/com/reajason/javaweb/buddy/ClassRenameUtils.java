package com.reajason.javaweb.buddy;

import com.reajason.javaweb.asm.InnerClassDiscovery;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.dynamic.scaffold.TypeValidation;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * @author ReaJason
 * @since 2025/5/22
 */
public class ClassRenameUtils {

    @SneakyThrows
    public static Map<String, byte[]> renamePackage(Class<?> clazz, String packageName) {
        String originalClassName = clazz.getName();
        String originalPackageName = clazz.getPackage().getName();
        String newClassName = packageName + "." + clazz.getSimpleName();
        Map<String, byte[]> map = new HashMap<>();
        try (DynamicType.Unloaded<?> make = new ByteBuddy()
                .redefine(clazz)
                .visit(new ClassRenameVisitorWrapper(originalClassName, newClassName))
                .visit(new TargetJreVersionVisitorWrapper(Opcodes.V1_6))
                .make()) {
            map.put(newClassName, make.getBytes());
        }
        Set<String> innerClassNames = InnerClassDiscovery.findAllInnerClasses(clazz);
        ClassFileLocator classFileLocator = ClassFileLocator.ForClassLoader.of(clazz.getClassLoader());
        TypePool typePool = TypePool.Default.of(classFileLocator);
        for (String innerClassName : innerClassNames) {
            TypeDescription innerTypeDesc = typePool.describe(innerClassName).resolve();
            String newInnerClassName = innerClassName.replace(originalClassName, newClassName);
            DynamicType.Builder<?> innerBuilder = new ByteBuddy()
                    .with(TypeValidation.DISABLED)
                    .redefine(innerTypeDesc, classFileLocator)
                    .visit(new ClassRenameVisitorWrapper(originalPackageName, packageName))
                    .visit(new TargetJreVersionVisitorWrapper(Opcodes.V1_6));

            try (DynamicType.Unloaded<?> unloaded = innerBuilder.make()) {
                for (Map.Entry<TypeDescription, byte[]> entry : unloaded.getAllTypes().entrySet()) {
                    map.put(newInnerClassName, entry.getValue());
                }
            }
        }
        return map;
    }
}
