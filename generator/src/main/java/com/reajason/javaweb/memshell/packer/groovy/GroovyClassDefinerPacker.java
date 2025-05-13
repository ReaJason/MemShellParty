package com.reajason.javaweb.memshell.packer.groovy;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
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
    public String pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        return template.replace("{{className}}", injectorClassName)
                .replace("{{base64Str}}", injectorBytesBase64Str);
    }
}