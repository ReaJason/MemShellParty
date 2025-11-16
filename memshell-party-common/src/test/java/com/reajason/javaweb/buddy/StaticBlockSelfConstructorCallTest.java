package com.reajason.javaweb.buddy;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * @author ReaJason
 * @since 2025/11/8
 */
class StaticBlockSelfConstructorCallTest {
    public static class MyClass {
        public static String message;

        static {
            System.out.println("hello world");
        }

        public MyClass() {
            message = "Hello World!";
            System.out.println("MyClass constructor called with message: " + message);
        }

        public String getMessage() {
            return message;
        }
    }

    @Test
    @SneakyThrows
    void test() {
        Class<? extends MyClass> rawClass = new ByteBuddy()
                .redefine(MyClass.class)
                .name("MyClass").make().load(StaticBlockSelfConstructorCallTest.class.getClassLoader()).getLoaded();
        assertNull(rawClass.getDeclaredField("message").get(null));

        Class<?> redefinedClass = StaticBlockSelfConstructorCall.extend(
                        new ByteBuddy()
                                .redefine(MyClass.class)
                                .name("MyClass")
                ).make().load(StaticBlockSelfConstructorCallTest.class.getClassLoader())
                .getLoaded();
        assertEquals("Hello World!", redefinedClass.getDeclaredField("message").get(null));
    }
}