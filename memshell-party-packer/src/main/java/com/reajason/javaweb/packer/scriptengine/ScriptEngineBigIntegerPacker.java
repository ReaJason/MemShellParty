package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;

import static com.reajason.javaweb.packer.scriptengine.DefaultScriptEnginePacker.scriptToSingleLine;

public class ScriptEngineBigIntegerPacker implements Packer {
    private final String jsTemplate = Util.loadTemplateFromResource("/memshell-party/ScriptEngineBigInteger.js");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return scriptToSingleLine(jsTemplate
                .replace("{{className}}", config.getClassName())
                .replace("{{bigIntegerStr}}", Packers.BigInteger.getInstance().pack(config)));
    }
}
