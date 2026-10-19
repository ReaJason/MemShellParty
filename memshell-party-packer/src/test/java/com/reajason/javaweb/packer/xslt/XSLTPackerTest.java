package com.reajason.javaweb.packer.xslt;

import com.reajason.javaweb.packer.ClassPackerConfig;
import org.junit.jupiter.api.Test;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class XSLTPackerTest {

    private static ClassPackerConfig config(String className) {
        ClassPackerConfig config = new ClassPackerConfig();
        byte[] classBytes = "hello".getBytes(StandardCharsets.UTF_8);
        config.setClassName(className);
        config.setClassBytes(classBytes);
        config.setClassBytesBase64Str(Base64.getEncoder().encodeToString(classBytes));
        return config;
    }

    @Test
    void packScriptEngine() {
        String payload = new XSLTScriptEnginePacker().pack(config("com.example.Test"));

        assertTrue(payload.startsWith("<xsl:stylesheet"));
        assertTrue(payload.contains("DatatypeConverter"));
        assertTrue(payload.contains("ScriptEngineManager"));
        // the inner js payload is base64 encoded, class name should not appear in plain text
        assertFalse(payload.contains("com.example.Test"));
    }

    /**
     * Xalan/XSLTC 把 XPath 字符串常量写进 translet 常量池，单个常量超过 65535 字节会
     * 抛 UTFDataFormatException；超长 base64 必须拆成 concat(...) 运行期拼接。
     */
    @Test
    void longPayloadUsesXPathConcatAndCompiles() throws Exception {
        ClassPackerConfig config = config("com.example.Test");
        char[] chars = new char[70_000];
        java.util.Arrays.fill(chars, 'A');
        config.setClassBytesBase64Str(new String(chars));

        String payload = new XSLTScriptEnginePacker().pack(config);
        assertTrue(payload.contains("concat("), "long base64 should be concatenated by XPath concat()");
        TransformerFactory.newInstance().newTemplates(new StreamSource(new StringReader(payload)));
    }
}
