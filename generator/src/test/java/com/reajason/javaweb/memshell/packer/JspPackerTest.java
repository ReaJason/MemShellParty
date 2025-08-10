package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.jsp.JspPacker;
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
        String jspContent = new JspPacker().pack(generateResult.toClassPackerConfig());
        assertTrue(jspContent.contains("String base64Str = \"hehe\";"));
    }
}