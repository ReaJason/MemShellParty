package com.reajason.javaweb.packer.groovy;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2025/5/11
 */
public class GroovyClassDefinerPacker implements Packer {
    private final String template = Util.loadTemplateFromResource("/memshell-party/shell.groovy");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}