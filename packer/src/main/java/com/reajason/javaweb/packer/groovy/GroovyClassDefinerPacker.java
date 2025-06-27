package com.reajason.javaweb.packer.groovy;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2025/5/11
 */
public class GroovyClassDefinerPacker implements Packer {
    String template = null;

    public GroovyClassDefinerPacker() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell.groovy")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}