package com.reajason.javaweb.packer.xxljob;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.reajason.javaweb.packer.ClassPackerConfig;
import groovy.lang.GroovyClassLoader;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2026/9/24
 */
class XxlJobJsonPackerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    void pack() throws Exception {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.reajason.javaweb.ErrorAbcdHandler");
        config.setClassBytesBase64Str("aGVsbG8=");
        String glueSource = extractGlueSource(config);
        assertTrue(glueSource.contains("'com.reajason.javaweb.ErrorAbcdHandler'"));
        compile(glueSource);
    }

    @Test
    void packClassNameWithLambdaSuffix() throws Exception {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1");
        config.setClassBytesBase64Str("aGVsbG8=");
        String glueSource = extractGlueSource(config);
        assertTrue(glueSource.contains("'le.gso.SzyHj.SOAPUtils$Proxy0$$Lambda$1'"));
        compile(glueSource);
    }

    /**
     * Glue 源码由 Groovy 编译，单个字符串字面量超过 65535 字符会被解析器拒绝。
     */
    @Test
    void longPayloadCompiles() throws Exception {
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName("com.reajason.javaweb.ErrorAbcdHandler");
        char[] chars = new char[70_000];
        java.util.Arrays.fill(chars, 'A');
        config.setClassBytesBase64Str(new String(chars));
        String glueSource = extractGlueSource(config);
        assertTrue(glueSource.contains("' + '"), "long payload should be concatenated at runtime");
        compile(glueSource);
    }

    @Test
    void escapesGlueSourceAsJsonString() throws Exception {
        String className = "com.example.Quote\"Backslash\\Line\nTab\tControl\u0001Name";
        ClassPackerConfig config = new ClassPackerConfig();
        config.setClassName(className);
        config.setClassBytesBase64Str("aGVsbG8=");

        JsonNode jsonNode = objectMapper.readTree(new XxlJobJsonPacker().pack(config));
        assertTrue(jsonNode.get("glueSource").asText().contains(className),
                "JSON 转义后应还原出原始 glueSource 内容");
    }

    private String extractGlueSource(ClassPackerConfig config) throws Exception {
        String payload = new XxlJobJsonPacker().pack(config);
        JsonNode jsonNode = objectMapper.readTree(payload);
        assertEquals("GLUE_GROOVY", jsonNode.get("glueType").asText());
        return jsonNode.get("glueSource").asText();
    }

    private void compile(String glueSource) {
        try (GroovyClassLoader classLoader = new GroovyClassLoader()) {
            classLoader.parseClass(glueSource);
        } catch (Exception e) {
            throw new AssertionError("glue source should compile, source: " + glueSource, e);
        }
    }
}
