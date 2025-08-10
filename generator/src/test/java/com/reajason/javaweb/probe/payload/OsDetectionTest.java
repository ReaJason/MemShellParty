package com.reajason.javaweb.probe.payload;

import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.asm.Advice;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

import static net.bytebuddy.matcher.ElementMatchers.named;

/**
 * @author ReaJason
 * @since 2025/7/26
 */
class OsDetectionTest {

    @Test
    @Disabled
    @SneakyThrows
    void testBytes() {
        byte[] bytes = new ByteBuddy()
                .redefine(Hello.class)
                .visit(Advice.to(OsProbe.class).on(named("toString")))
                .make().getBytes();
        Files.write(Paths.get("osDetection.class"), bytes);
    }

    @Test
    void test() {
        System.out.println(System.getProperty("os.name").toLowerCase());
    }
}