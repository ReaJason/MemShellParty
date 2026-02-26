package com.reajason.javaweb.packer;

import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Objects;
import java.util.zip.GZIPOutputStream;

/**
 * @author ReaJason
 * @since 2025/9/1
 */
public class Util {

    @SneakyThrows
    public static String loadTemplateFromResource(String resourceName) {
        try (InputStream stream = Util.class.getResourceAsStream(resourceName)) {
            return IOUtils.toString(Objects.requireNonNull(stream), Charset.defaultCharset());
        }
    }

    @SneakyThrows
    public static byte[] gzipCompress(byte[] data) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try (GZIPOutputStream gzip = new GZIPOutputStream(out)) {
            gzip.write(data);
        }
        return out.toByteArray();
    }
}
