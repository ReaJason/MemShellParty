package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class DefaultScriptEnginePacker implements Packer {
    String jsTemplate = null;

    public DefaultScriptEnginePacker() {
        try {
            jsTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/DefaultScriptEngine.js")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jsTemplate
                .replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str())
                .replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
