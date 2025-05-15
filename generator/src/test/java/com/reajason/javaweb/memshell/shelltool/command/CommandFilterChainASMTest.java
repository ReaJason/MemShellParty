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
import org.objectweb.asm.commons.AdviceAdapter;
import org.objectweb.asm.commons.Method;

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

    public static class CustomMethodVisitor extends AdviceAdapter {
        private static final Method CUSTOM_EQUALS_CONSTRUCTOR = Method.getMethod("void <init> ()");
        private static final Method CUSTOM_EQUALS_METHOD = Method.getMethod("boolean equals (java.lang.Object)");
        private final Type customEqualsType;

        protected CustomMethodVisitor(MethodVisitor mv, int access, String name, String descriptor) {
            super(Opcodes.ASM9, mv, access, name, descriptor);
            CommandFilterChain.paramName = "paramName";
            customEqualsType = Type.getObjectType(CommandFilterChain.class.getName().replace('.', '/'));
        }

        @Override
        protected void onMethodEnter() {
            System.out.println("Enter CustomMethodVisitor");
            loadArgArray();
            newInstance(customEqualsType);
            dup();
            invokeConstructor(customEqualsType, CUSTOM_EQUALS_CONSTRUCTOR);
            swap();
            invokeVirtual(customEqualsType, CUSTOM_EQUALS_METHOD);
            Label skipReturnLabel = new Label();
            mv.visitJumpInsn(IFEQ, skipReturnLabel);
            mv.visitInsn(RETURN);
            mark(skipReturnLabel);
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
                    return new CustomMethodVisitor(mv, access, name, descriptor);
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        byte[] bytes2 = ClassRenameUtils.renameClass(cw.toByteArray(), TestFilterChain.class.getName() + "Asm");
//        IOUtils.write(bytes2, new FileOutputStream(new File("godzilla2.class")));
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
