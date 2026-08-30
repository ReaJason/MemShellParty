package com.reajason.javaweb.packer.freemarker;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FreemarkerSpELSpringGzipPackerTest {

    private static ClassPackerConfig config(String className) {
        ClassPackerConfig config = new ClassPackerConfig();
        byte[] classBytes = "hello".getBytes(StandardCharsets.UTF_8);
        config.setClassName(className);
        config.setClassBytes(classBytes);
        config.setClassBytesBase64Str(Base64.getEncoder().encodeToString(classBytes));
        return config;
    }

    @Test
    void pack() {
        String payload = new FreemarkerSpELSpringGzipPacker().pack(config("com.example.Test"));

        assertTrue(payload.startsWith("${\"freemarker.template.utility.ObjectConstructor\"?new()"));
        assertTrue(payload.contains("SpelExpressionParser"));
        assertTrue(payload.contains("Base64Utils"));
        assertTrue(payload.contains("GZIPInputStream"));
        assertTrue(payload.contains("com.example.Test"));
    }

    @Test
    void packJdk17() {
        FreemarkerSpELSpringGzipJDK17Packer packer = new FreemarkerSpELSpringGzipJDK17Packer();

        assertDoesNotThrow(() -> packer.pack(config("org.springframework.expression.Test")));
        assertThrows(UnsupportedOperationException.class,
                () -> packer.pack(config("com.example.Test")));
    }
}
