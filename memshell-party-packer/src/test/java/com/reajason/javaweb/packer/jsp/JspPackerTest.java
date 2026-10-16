package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
class JspPackerTest {

    @Test
    void pack() {
        MemShellResult generateResult = MemShellResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String jspContent = new JspPacker().pack(ClassPackerConfig.from(generateResult));
        assertTrue(jspContent.contains("String base64Str = \"hehe\";"));
    }
}