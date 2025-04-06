package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;
import org.jetbrains.annotations.NotNull;

import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author ReaJason
 */
public class MethodCallReplaceVisitorWrapper implements AsmVisitorWrapper.ForDeclaredMethods.MethodVisitorWrapper {

    private final String targetClassName;
    private final Set<String> replaceClassNames;

    public MethodCallReplaceVisitorWrapper(String targetClassName, Set<String> replaceClassNames) {
        this.targetClassName = targetClassName.replace(".", "/");
        this.replaceClassNames = replaceClassNames.stream().map(s -> s.replace(".", "/")).collect(Collectors.toSet());
    }

    @NotNull
    @Override
    public MethodVisitor wrap(@NotNull TypeDescription instrumentedType,
                              @NotNull MethodDescription instrumentedMethod,
                              @NotNull MethodVisitor methodVisitor,
                              @NotNull Implementation.Context implementationContext,
                              @NotNull TypePool typePool,
                              int writerFlags,
                              int readerFlags) {
        return new MethodVisitor(Opcodes.ASM9, methodVisitor) {
            @Override
            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                if (opcode == Opcodes.INVOKESTATIC
                        && replaceClassNames.contains(owner)) {
                    super.visitMethodInsn(Opcodes.INVOKESTATIC,
                            targetClassName,
                            name,
                            descriptor,
                            false);
                } else {
                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                }
            }
        };
    }
}