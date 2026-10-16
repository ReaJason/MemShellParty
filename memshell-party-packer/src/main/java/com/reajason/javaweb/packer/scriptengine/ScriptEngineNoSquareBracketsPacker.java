package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;

public class ScriptEngineNoSquareBracketsPacker implements Packer {
    private final String jsTemplate = Util.loadTemplateFromResource("/memshell-party/ScriptEngineNoSquareBrackets.js");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return scriptToSingleLine(jsTemplate
                .replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str()));
    }

    public static String scriptToSingleLine(String script) {
        return script.replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
