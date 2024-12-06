package com.reajason.javaweb.buddy;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
class ByPassJdkModuleInterceptorTest {

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
    void test() {
        DynamicType.Builder<?> builder = new ByteBuddy()
                .redefine(TestClass.class)
                .name("com.reajason.javaweb.buddy.ByPassJdkModuleInterceptorTest$TestClass1");
        builder = ByPassJdkModuleInterceptor.extend(builder);
        try (DynamicType.Unloaded<?> make = builder.make()) {
            byte[] bytes = make.getBytes();
            Files.write(Paths.get("build", "classes", "TestClass1.class"), bytes);
        }
    }

}