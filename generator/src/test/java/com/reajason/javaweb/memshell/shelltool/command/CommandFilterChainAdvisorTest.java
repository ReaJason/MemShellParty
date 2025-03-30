package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.memshell.shelltool.DelegatingServletOutputStream;
import com.reajason.javaweb.memshell.shelltool.FilterChainInterface;
import com.reajason.javaweb.memshell.shelltool.TestFilterChain;
import lombok.SneakyThrows;
import net.bytebuddy.agent.ByteBuddyAgent;
import net.bytebuddy.agent.builder.AgentBuilder;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.dynamic.ClassFileLocator;
import net.bytebuddy.dynamic.loading.ByteArrayClassLoader;
import net.bytebuddy.matcher.ElementMatchers;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.servlet.FilterChain;
import javax.servlet.ServletOutputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.ByteArrayOutputStream;
import java.lang.instrument.ClassFileTransformer;
import java.nio.charset.StandardCharsets;

import static net.bytebuddy.matcher.ElementMatchers.none;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

/**
 * @author ReaJason
 * @since 2025/3/30
 */
@ExtendWith(MockitoExtension.class)
public class CommandFilterChainAdvisorTest {

    @Mock
    ServletRequest mockRequest;

    @Mock
    ServletResponse mockResponse;

    Object instance;

    static ClassFileTransformer classFileTransformer;

    @BeforeEach
    @SneakyThrows
    void setUp() {
        ByteBuddyAgent.install();
        ClassLoader classLoader = new ByteArrayClassLoader.ChildFirst(CommandFilterChainAdvisorTest.class.getClassLoader(),
                ClassFileLocator.ForClassLoader.readToNames(TestFilterChain.class),
                ByteArrayClassLoader.PersistenceHandler.MANIFEST);
        classFileTransformer = new AgentBuilder.Default()
                .ignore(none())
                .type(ElementMatchers.is(TestFilterChain.class), ElementMatchers.is(classLoader)).transform((
                        (builder, typeDescription, c, module, protectionDomain) ->
                                builder.visit(Advice.to(CommandFilterChainAdvisor.class).on(ElementMatchers.named("doFilter")))))
                .installOnByteBuddyAgent();
        Class<?> clazz = classLoader.loadClass(TestFilterChain.class.getName());
        instance = spy(clazz.newInstance());
    }

    @AfterEach
    void tearDown() {
        ByteBuddyAgent.getInstrumentation().removeTransformer(classFileTransformer);
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
