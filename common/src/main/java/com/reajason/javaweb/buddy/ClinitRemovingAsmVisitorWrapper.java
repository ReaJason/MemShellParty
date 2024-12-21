package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.OpenedClassReader;
import org.jetbrains.annotations.NotNull;

/**
 * 移除静态代码块
 *
 * @author ReaJason
 */
public enum ClinitRemovingAsmVisitorWrapper implements AsmVisitorWrapper {

    /**
     * The singleton instance.
     */
    INSTANCE;

    private static final String CLINIT = "<clinit>";

    @Override
    public int mergeWriter(int flags) {
        return flags;
    }

    @Override
    public int mergeReader(int flags) {
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
        return new ClinitRemovingClassVisitor(classVisitor);
    }

    protected static class ClinitRemovingClassVisitor extends ClassVisitor {
        protected ClinitRemovingClassVisitor(ClassVisitor classVisitor) {
            super(OpenedClassReader.ASM_API, classVisitor);
        }

        @Override
        public MethodVisitor visitMethod(
                int modifiers, String name, String descriptor, String signature, String[] exception) {
            MethodVisitor methodVisitor =
                    super.visitMethod(modifiers, name, descriptor, signature, exception);
            return name.equals(CLINIT)
                    ? null
                    : methodVisitor;
        }
    }
}