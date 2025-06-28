package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEnginePacker implements Packer {
    String jsTemplate = null;

    public ScriptEnginePacker() {
        try {
            jsTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell.js")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jsTemplate
                .replace("{{base64Str}}", config.getClassBytesBase64Str())
                .replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
