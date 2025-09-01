package com.reajason.javaweb.packer;

import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Objects;

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
}
