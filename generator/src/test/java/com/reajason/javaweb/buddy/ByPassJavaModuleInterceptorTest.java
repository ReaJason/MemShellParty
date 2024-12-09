package com.reajason.javaweb.buddy;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;

import java.lang.reflect.InaccessibleObjectException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.condition.JRE.JAVA_17;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
class ByPassJavaModuleInterceptorTest {
    static class TestClass {
        static {
            System.out.println("TestClass");
        }

        public TestClass() {
        }


        public String hello() {
            return "hello";
        }
    }

    @Test
    @SneakyThrows
    @EnabledOnJre(JAVA_17)
    void testByPassModule() {
        Method defineClass = ClassLoader.class.getDeclaredMethod("defineClass", byte[].class, int.class, int.class);
        assertThrows(InaccessibleObjectException.class, () -> {
            defineClass.setAccessible(true);
        });
        ByPassJavaModuleInterceptor.enter(this.getClass());
        assertDoesNotThrow(() -> {
            defineClass.setAccessible(true);
        });
    }

    @Test
    @SneakyThrows
    void test() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(TestClass.class)
                .name("com.reajason.javaweb.buddy.ByPassJdkModuleInterceptorTest$TestClass1");
        builder = ByPassJavaModuleInterceptor.extend(builder);
        try (DynamicType.Unloaded<?> make = builder.make()) {
            byte[] bytes = make.getBytes();
            Files.write(Paths.get("build", "classes", "TestClass1.class"), bytes);
            Class<?> loaded = make.load(Thread.currentThread().getContextClassLoader()).getLoaded();
            assertNotNull(loaded.getDeclaredMethod("byPassJdkModule"));
        }
    }

}