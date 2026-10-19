package com.reajason.javaweb.packer.deserialize.hessian;

import org.junit.jupiter.api.Test;

import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamSource;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Hessian XSLT 链路同样由 Xalan/XSLTC 编译样式表，超长 JS 源码必须拆成
 * XPath concat()，否则 translet 常量池会撞上 65535 上限。
 */
class XSLTScriptEngineTest {

    @Test
    void longPayloadUsesXPathConcatAndCompiles() throws Exception {
        byte[] bytes = new byte[70_000];
        String xml = XSLTScriptEngine.createXml(bytes, "com.example.Test");

        assertTrue(xml.contains("concat("), "long js source should be concatenated by XPath concat()");
        TransformerFactory.newInstance().newTemplates(new StreamSource(new StringReader(xml)));
    }
}
