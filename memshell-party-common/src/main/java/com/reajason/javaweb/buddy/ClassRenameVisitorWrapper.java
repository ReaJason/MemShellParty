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
import org.jetbrains.annotations.NotNull;

/**
 * @author ReaJason
 * @since 2025/3/27
 */
public class ClassRenameVisitorWrapper implements AsmVisitorWrapper {
    public final String originalClassName;
    public final String newClassName;

    public ClassRenameVisitorWrapper(String originalClassName, String newClassName) {
        this.originalClassName = originalClassName.replace('.', '/');
        this.newClassName = newClassName.replace('.', '/');
    }


    @Override
    public int mergeReader(int flags) {
        return flags;
    }

    @Override
    public int mergeWriter(int flags) {
        return flags;
    }

    @NotNull
    @Override
    public ClassVisitor wrap(@NotNull TypeDescription instrumentedType,
                             @NotNull ClassVisitor classVisitor,
                             @NotNull Implementation.Context implementationContext,
                             @NotNull TypePool typePool,
                             @NotNull FieldList<FieldDescription.InDefinedShape> fields,
                             @NotNull MethodList<?> methods,
                             int writerFlags,
                             int readerFlags) {
        return new ClassRemapper(
                classVisitor,
                new Remapper() {
                    @Override
                    public String map(String typeName) {
                        if (typeName.equals(originalClassName)) {
                            return newClassName;
                        } else if (typeName.startsWith(originalClassName)) {
                            return typeName.replace(originalClassName, newClassName);
                        } else {
                            return typeName;
                        }
                    }
                });
    }
}
