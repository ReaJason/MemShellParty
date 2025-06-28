package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
class ScriptEnginePackerTest {

    @Test
    void pack() {
        GenerateResult generateResult = GenerateResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String jsContent = new ScriptEnginePacker().pack(generateResult.toClassPackerConfig());
        assertTrue(jsContent.contains("var base64Str = \"hehe\";"));
    }
}