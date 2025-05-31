package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.scriptengine.ScriptEnginePacker;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnJre;
import org.junit.jupiter.api.condition.JRE;

import javax.script.ScriptEngineManager;

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
        String jsContent = new String(new ScriptEnginePacker().pack(generateResult));
        System.out.println(jsContent);
        assertTrue(jsContent.contains("var base64Str = \"hehe\";"));
    }
}