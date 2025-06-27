package com.reajason.javaweb.packer.base64;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 * @since 2025/1/22
 */
public class GzipBase64Packer implements Packer {
    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return Base64.getEncoder().encodeToString(gzipCompress(config.getClassBytes()));
    }

    public static byte[] gzipCompress(byte[] data) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }
}
