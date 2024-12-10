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
 * Servlet 包名替换，扫描包中所有 javax/servlet 将其替换成 jakarta/servlet。
 *
 * @author ReaJason
 * @since 2024/11/23
 */
public class ServletRenameVisitorWrapper implements AsmVisitorWrapper {
    public static ServletRenameVisitorWrapper INSTANCE = new ServletRenameVisitorWrapper();

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
                        if (typeName.startsWith("javax/servlet/")) {
                            return typeName.replaceFirst("javax", "jakarta");
                        } else {
                            return typeName;
                        }
                    }
                });
    }
}
