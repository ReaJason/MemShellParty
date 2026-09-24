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

    private void compile(String script) {
        try (GroovyClassLoader classLoader = new GroovyClassLoader()) {
            classLoader.parseClass(script);
        } catch (Exception e) {
            throw new AssertionError("groovy script should compile, script: " + script, e);
        }
    }
}
