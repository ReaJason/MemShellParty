package com.reajason.javaweb.buddy;

import net.bytebuddy.description.method.MethodDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.implementation.bytecode.ByteCodeAppender;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;

import static net.bytebuddy.matcher.ElementMatchers.isTypeInitializer;

/**
 * 在静态代码块中添加构造方法调用例如：
 * static {
 *     new Injector();
 * }
 *
 * @author ReaJason
 * @since 2025/8/12
 */
public class StaticBlockSelfConstructorCall implements ByteCodeAppender {

    public static StaticBlockSelfConstructorCall INSTANCE = new StaticBlockSelfConstructorCall();

    public static DynamicType.Builder<?> extend(DynamicType.Builder<?> builder) {
        return builder
                .invokable(isTypeInitializer())
                .intercept(new Implementation.Simple(StaticBlockSelfConstructorCall.INSTANCE));
    }

    @Override
    public Size apply(MethodVisitor methodVisitor,
                      Implementation.Context implementationContext,
                      MethodDescription methodDescription) {
        methodVisitor.visitTypeInsn(Opcodes.NEW, implementationContext.getInstrumentedType().getInternalName());
        methodVisitor.visitInsn(Opcodes.DUP);
        methodVisitor.visitMethodInsn(Opcodes.INVOKESPECIAL,
                implementationContext.getInstrumentedType().getInternalName(),
                "<init>",
                "()V",
                false);
        methodVisitor.visitInsn(Opcodes.POP);
        methodVisitor.visitInsn(Opcodes.RETURN);
        return new Size(2, 2);
    }
}
