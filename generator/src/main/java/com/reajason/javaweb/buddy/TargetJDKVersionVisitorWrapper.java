package com.reajason.javaweb.buddy;

import com.reajason.javaweb.config.Constants;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import net.bytebuddy.utility.nullability.MaybeNull;
import org.jetbrains.annotations.NotNull;

/**
 * @author ReaJason
 */
public class TargetJDKVersionVisitorWrapper implements AsmVisitorWrapper {

    public static final TargetJDKVersionVisitorWrapper DEFAULT = new TargetJDKVersionVisitorWrapper();

    private final int targetJdkVersion;

    public TargetJDKVersionVisitorWrapper() {
        targetJdkVersion = Constants.DEFAULT_VERSION;
    }

    public TargetJDKVersionVisitorWrapper(int targetJdkVersion) {
        this.targetJdkVersion = targetJdkVersion;
    }

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
                             @NotNull ClassVisitor classVisitor, @NotNull Implementation.Context implementationContext,
                             @NotNull TypePool typePool, @NotNull FieldList<FieldDescription.InDefinedShape> fields,
                             @NotNull MethodList<?> methods, int writerFlags, int readerFlags) {
        return new ClassVisitor(Opcodes.ASM9, classVisitor) {
            @Override
            public void visit(int version, int modifiers, String name, @MaybeNull String signature, @MaybeNull String superClassName, @MaybeNull String[] interfaceName) {
                super.visit(targetJdkVersion, modifiers, name, signature, superClassName, interfaceName);
            }
        };
    }
}