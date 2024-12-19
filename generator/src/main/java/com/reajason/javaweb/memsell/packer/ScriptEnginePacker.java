package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
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
    public String pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        return jsTemplate.replace("{{className}}", injectorClassName)
                .replace("{{base64Str}}", injectorBytesBase64Str)
                .replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
