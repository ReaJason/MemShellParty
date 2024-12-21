package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
class FreemarkerPackerTest {
    FreemarkerPacker packer = new FreemarkerPacker();

    @Test
    void test() {
        GenerateResult generateResult = GenerateResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String content = new String(packer.pack(generateResult));
        System.out.println(content);
        assertTrue(content.contains("var className = \"hehe\";"));
        assertTrue(content.contains("var base64Str = \"hehe\";"));
    }
}