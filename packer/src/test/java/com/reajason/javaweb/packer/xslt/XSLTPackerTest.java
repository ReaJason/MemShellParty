package com.reajason.javaweb.packer.xslt;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XSLTPackerTest {

    private static ClassPackerConfig config(String className) {
        ClassPackerConfig config = new ClassPackerConfig();
        byte[] classBytes = "hello".getBytes(StandardCharsets.UTF_8);
        config.setClassName(className);
        config.setClassBytes(classBytes);
        config.setClassBytesBase64Str(Base64.getEncoder().encodeToString(classBytes));
        return config;
    }

    @Test
    void packScriptEngine() {
        String payload = new XSLTScriptEnginePacker().pack(config("com.example.Test"));

        assertTrue(payload.startsWith("<xsl:stylesheet"));
        assertTrue(payload.contains("DatatypeConverter"));
        assertTrue(payload.contains("ScriptEngineManager"));
        // the inner js payload is base64 encoded, class name should not appear in plain text
        assertFalse(payload.contains("com.example.Test"));
    }
}
