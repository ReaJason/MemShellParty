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
 * @author ReaJason
 * @since 2024/11/23
 */
public class ServletRenameVisitorWrapper implements AsmVisitorWrapper {
    @Override
    public int mergeReader(int flags) {
        return 0;
    }

    @Override
    public int mergeWriter(int flags) {
        return 0;
    }

    @Override
    public ClassVisitor wrap(
            TypeDescription instrumentedType,
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
                        if (typeName.startsWith("javax/servlet/")) {
                            return typeName.replaceFirst("javax", "jakarta");
                        } else {
                            return typeName;
                        }
                    }
                });
    }
}
