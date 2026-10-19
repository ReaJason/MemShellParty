package com.reajason.javaweb.packer.groovy;

import com.reajason.javaweb.packer.ClassPackerConfig;
import groovy.lang.GroovyClassLoader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2026/9/24
 */
class GroovyClassDefinerPackerTest {

    @Test
    void pack() {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.reajason.javaweb.ErrorAbcdHandler");
        config.setClassBytesBase64Str("aGVsbG8=");
        String script = new GroovyClassDefinerPacker().pack(config);
        assertTrue(script.contains("'com.reajason.javaweb.ErrorAbcdHandler'"));
        compile(script);
    }

    @Test
    void packClassNameWithLambdaSuffix() {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1");
        config.setClassBytesBase64Str("aGVsbG8=");
        String script = new GroovyClassDefinerPacker().pack(config);
        assertTrue(script.contains("'le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1'"));
        compile(script);
    }

    /**
     * Groovy 解析器直接拒绝超过 65535 字符的单个字符串字面量，超长 payload 必须拆开拼接。
     */
    @Test
    void longPayloadCompiles() {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.reajason.javaweb.ErrorAbcdHandler");
        config.setClassBytesBase64Str(repeat('A', 70_000));
        String script = new GroovyClassDefinerPacker().pack(config);
        assertTrue(script.contains("' + '"), "long payload should be concatenated at runtime");
        compile(script);
    }

    private static String repeat(char ch, int count) {
        char[] chars = new char[count];
        java.util.Arrays.fill(chars, ch);
        return new String(chars);
    }

    private void compile(String script) {
        try (GroovyClassLoader classLoader = new GroovyClassLoader()) {
            classLoader.parseClass(script);
        } catch (Exception e) {
            throw new AssertionError("groovy script should compile, script: " + script, e);
        }
    }
}
