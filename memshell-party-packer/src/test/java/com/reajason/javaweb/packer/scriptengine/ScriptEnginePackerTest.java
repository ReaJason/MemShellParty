package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import javax.script.Compilable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
class ScriptEnginePackerTest {

    @Test
    void pack() {
        MemShellResult generateResult = MemShellResult.builder()
                .injectorClassName("hehe")
                .injectorBytesBase64Str("hehe").build();
        String jsContent = new ScriptEnginePacker().pack(ClassPackerConfig.from(generateResult));
        assertTrue(jsContent.contains("var base64Str = \"hehe\";"));
    }

    /**
     * Nashorn/Rhino 自己会拆分超长字符串常量，不需要在打包器里处理；这里锁住该前提。
     */
    @Test
    void longPayloadCompilesWithBuiltInEngine() throws Exception {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.example.Test");
        char[] chars = new char[70_000];
        java.util.Arrays.fill(chars, 'A');
        config.setClassBytesBase64Str(new String(chars));

        String js = new ScriptEnginePacker().pack(config);
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        assertNotNull(engine, "need a JDK with Nashorn/Rhino to run this test");
        ((Compilable) engine).compile(js);
    }
}