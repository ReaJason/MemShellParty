package com.reajason.javaweb.buddy;

import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.matcher.ElementMatchers;
import net.bytebuddy.pool.TypePool;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import static net.bytebuddy.jar.asm.Opcodes.INVOKEVIRTUAL;
import static net.bytebuddy.jar.asm.Opcodes.POP;

/**
 * Debug 信息打印移除器
 * 目前仅支持移除以下几种
 * <br />
 * 1. System.out.println() - （printf 还不支持）
 * 2. e.printStackTrace()
 * 3. Logger.info (java.util)
 *
 * @author ReaJason
 */
public class LogRemoveMethodVisitor implements AsmVisitorWrapper.ForDeclaredMethods.MethodVisitorWrapper {
    public static final LogRemoveMethodVisitor INSTANCE = new LogRemoveMethodVisitor();

    public static DynamicType.Builder<?> extend(DynamicType.Builder<?> builder) {
        return builder.visit(
                new AsmVisitorWrapper.ForDeclaredMethods()
                        .method(ElementMatchers.any(), LogRemoveMethodVisitor.INSTANCE));
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
                if ((opcode == INVOKEVIRTUAL && owner.equals("java/io/PrintStream") && name.equals("println"))
                        || (opcode == INVOKEVIRTUAL && owner.endsWith("Exception") && name.equals("printStackTrace"))
                        || (opcode == INVOKEVIRTUAL && owner.equals("java/util/logging/Logger") && (name.equals("info") || name.equals("warning")))
                ) {
                    String[] args = descriptor.substring(1, descriptor.indexOf(')')).split(";");
                    for (String arg : args) {
                        if (StringUtils.isNotBlank(arg)) {
                            super.visitInsn(POP);
                        }
                    }
                    super.visitInsn(POP);
                } else {
                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                }
            }
        };
    }
}