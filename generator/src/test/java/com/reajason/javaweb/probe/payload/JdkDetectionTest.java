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
 * @since 2025/8/1
 */
class JdkDetectionTest {

    @Test
    @Disabled
    @SneakyThrows
    void test() {
        byte[] bytes = new ByteBuddy()
                .redefine(Hello.class)
                .visit(Advice.to(JdkProbe.class).on(named("toString")))
                .make().getBytes();
        Files.write(Paths.get("jdkDetection.class"), bytes);
    }
}