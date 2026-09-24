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
