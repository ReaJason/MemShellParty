package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/3
 */
public class ScriptEnginePacker implements Packer {
    @Override
    @SneakyThrows
    public byte[] pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        String jsTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell.js")), Charset.defaultCharset());
        return jsTemplate.replace("{{className}}", injectorClassName).replace("{{base64Str}}", injectorBytesBase64Str).getBytes();
    }
}
