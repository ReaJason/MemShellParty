package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.generator.processors.ListenerBuilderModifier;
import com.reajason.javaweb.memshell.server.Tomcat;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.description.type.TypeDescription;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.platform.commons.util.ReflectionUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2025/9/16
 */
class ListenerGeneratorTest {

    public static class L {
        public Object getResponseFromRequest(Object request) {
            return null;
        }
    }

    public static class J {
        public HttpServletResponse getResponseFromRequest(HttpServletRequest request) {
            return null;
        }
    }

    public static class FakeRequest {
        public Object response = "i'm a good boy";
    }

    @Test
    void testNoGetResponseFromRequest() {
        DynamicType.Builder<?> builder = new ByteBuddy().redefine(Object.class);
        Assertions.assertThrows(GenerationException.class, () -> ListenerBuilderModifier.modifier(builder, Tomcat.ListenerInterceptor.class, TypeDescription.ForLoadedType.of(Object.class), "hello.world"));
    }

    @Test
    void testGetResponseFromRequestSignatureError() {
        DynamicType.Builder<?> builder = new ByteBuddy().redefine(J.class);
        Assertions.assertThrows(GenerationException.class, () -> ListenerBuilderModifier.modifier(builder, Tomcat.ListenerInterceptor.class, TypeDescription.ForLoadedType.of(J.class), "hello.world"));
    }

    @Test
    @SneakyThrows
    void test() {
        String className = "hello.world";
        DynamicType.Builder<?> build = ListenerBuilderModifier.modifier(new ByteBuddy().redefine(L.class).name(className), Tomcat.ListenerInterceptor.class, TypeDescription.ForLoadedType.of(L.class), className);
        Class<?> clazz = build.make().load(getClass().getClassLoader()).getLoaded();
        Object obj = clazz.newInstance();
        Method getResponseFromRequest = clazz.getDeclaredMethod("getResponseFromRequest", Object.class);
        getResponseFromRequest.setAccessible(true);
        Object response = getResponseFromRequest.invoke(obj, new FakeRequest());
        assertEquals("i'm a good boy", response);
    }
}