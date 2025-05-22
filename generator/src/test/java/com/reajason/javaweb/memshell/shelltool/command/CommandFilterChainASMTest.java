package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.shelltool.DelegatingServletOutputStream;
import com.reajason.javaweb.memshell.shelltool.FilterChainInterface;
import com.reajason.javaweb.memshell.shelltool.TestFilterChain;
import com.reajason.javaweb.util.ClassUtils;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.objectweb.asm.*;

import javax.servlet.FilterChain;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

/**
 * @author ReaJason
 * @since 2025/3/30
 */
@ExtendWith(MockitoExtension.class)
public class CommandFilterChainASMTest {

    @Mock
    HttpServletRequest mockRequest;

    @Mock
    HttpServletResponse mockResponse;

    Object instance;

    @SuppressWarnings("all")
    public static class CustomMethodVisitor extends MethodVisitor {
        private final Type customEqualsType;
        private final Type[] argumentTypes;
        private final String className;

        protected CustomMethodVisitor(MethodVisitor mv, Type[] argTypes) {
            super(Opcodes.ASM9, mv);
            this.argumentTypes = argTypes;
            Command.paramName = "paramName";
            className = Command.class.getName();
            customEqualsType = Type.getObjectType(Command.class.getName().replace('.', '/'));
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
                mv.visitVarInsn(argumentTypes[i].getOpcode(Opcodes.ILOAD), getArgIndex(i));
                mv.visitInsn(Type.getType(Object.class).getOpcode(Opcodes.IASTORE));
            }
        }

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
    }

    @BeforeEach
    @SneakyThrows
    void setUp() {
        byte[] bytes = IOUtils.toByteArray(Objects.requireNonNull(TestFilterChain.class.getClassLoader().getResource(TestFilterChain.class.getName().replace('.', '/') + ".class")));
        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("doFilter".equals(name)) {
                    Type[] argTypes = Type.getArgumentTypes(descriptor);
                    return new CustomMethodVisitor(mv, argTypes);
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        byte[] bytes2 = ClassRenameUtils.renameClass(cw.toByteArray(), TestFilterChain.class.getName() + "Asm");
        IOUtils.write(bytes2, new FileOutputStream(new File("godzilla2.class")));
        Class<?> clazz = ClassUtils.defineClass(bytes2);
        instance = spy(clazz.newInstance());
    }

    @Test
    @SneakyThrows
    void testInvokeParam() {
        when(mockRequest.getParameter("paramName")).thenReturn("id");
        ByteArrayOutputStream capturedOutput = new ByteArrayOutputStream();
        ServletOutputStream servletOutputStream = new DelegatingServletOutputStream(capturedOutput);
        when(mockResponse.getOutputStream()).thenReturn(servletOutputStream);

        instance.getClass().getMethod("doFilter", ServletRequest.class, ServletResponse.class, FilterChain.class).invoke(instance, mockRequest, mockResponse, null);
        String output = capturedOutput.toString(StandardCharsets.UTF_8);
        assertTrue(output.contains("uid="));

        verify(((FilterChainInterface) instance), never()).doFilterInternal();
    }

    @Test
    @SneakyThrows
    void testNotParameter() {
        when(mockRequest.getParameter("paramName")).thenReturn(null);

        instance.getClass().getMethod("doFilter", ServletRequest.class, ServletResponse.class, FilterChain.class).invoke(instance, mockRequest, mockResponse, null);

        verify(((FilterChainInterface) instance), atLeastOnce()).doFilterInternal();
    }
}
