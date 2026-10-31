package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.Remapper;
import net.bytebuddy.pool.TypePool;

/**
 * 按类名或包名改写类文件里的所有类型引用。
 *
 * @author ReaJason
 * @since 2025/3/27
 */
public class ClassRenameVisitorWrapper implements AsmVisitorWrapper {
    public final String originalClassName;
    public final String newClassName;
    private final boolean matchesInnerClasses;

    public ClassRenameVisitorWrapper(String originalClassName, String newClassName) {
        this(originalClassName, newClassName, true);
    }

    private ClassRenameVisitorWrapper(String originalName, String newName, boolean matchesInnerClasses) {
        this.originalClassName = originalName.replace('.', '/');
        this.newClassName = newName.replace('.', '/');
        this.matchesInnerClasses = matchesInnerClasses;
    }

    /**
     * 包名替换：只匹配 {@code 包名/} 下的类型，不碰同前缀的其他包或形如 {@code 包名$X} 的顶层类。
     */
    public static ClassRenameVisitorWrapper forPackage(String originalPackage, String newPackage) {
        return new ClassRenameVisitorWrapper(originalPackage, newPackage, false);
    }

    @Override
    public int mergeReader(int flags) {
        return flags;
    }

    @Override
    public int mergeWriter(int flags) {
        return flags;
    }

    @Override
    public ClassVisitor wrap(TypeDescription instrumentedType,
                             ClassVisitor classVisitor,
                             Implementation.Context implementationContext,
                             TypePool typePool,
                             FieldList<FieldDescription.InDefinedShape> fields,
                             MethodList<?> methods,
                             int writerFlags,
                             int readerFlags) {
        return new ClassRemapper(
                classVisitor,
                new Remapper() {
                    @Override
                    public String map(String typeName) {
                        if (typeName.equals(originalClassName)) {
                            return newClassName;
                        }
                        String boundary = matchesInnerClasses ? "$" : "/";
                        if (typeName.startsWith(originalClassName + boundary)) {
                            return newClassName + typeName.substring(originalClassName.length());
                        }
                        return typeName;
                    }
                });
    }
}
