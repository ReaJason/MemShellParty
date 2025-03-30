package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.shelltool.DelegatingServletOutputStream;
import com.reajason.javaweb.memshell.shelltool.FilterChainInterface;
import com.reajason.javaweb.memshell.shelltool.TestFilterChain;
import com.reajason.javaweb.util.ClassUtils;
import lombok.SneakyThrows;
import me.n1ar4.clazz.obfuscator.api.ClassObf;
import me.n1ar4.clazz.obfuscator.api.Result;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;
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
    ServletRequest mockRequest;

    @Mock
    ServletResponse mockResponse;

    Object instance;

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
                    Type[] argumentTypes = Type.getArgumentTypes(descriptor);
                    return new CommandFilterChainAsmMethodVisitor(mv, argumentTypes);
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        byte[] bytes2 = ClassRenameUtils.renameClass(cw.toByteArray(), TestFilterChain.class.getName() + "Asm");
        BaseConfig config = BaseConfig.Default();
        config.setIgnorePublic(true);
        config.setEnableMethodName(false);
        config.setEnableParamName(false);
        config.setEnableAES(false);
        config.setEnableAdvanceString(false);
        ClassObf classObf = new ClassObf(config);
        Result run = classObf.run(bytes2);
        bytes2 = run.getData();
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
