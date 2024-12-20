package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.config.GenerateResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
class JspPackerTest {

    @Test
    void pack() {
        GenerateResult generateResult = GenerateResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String jspContent = new String(new JspPacker().pack(generateResult));
        assertTrue(jspContent.contains("String className = \"hehe\";"));
        assertTrue(jspContent.contains("String base64Str = \"hehe\";"));
    }
}