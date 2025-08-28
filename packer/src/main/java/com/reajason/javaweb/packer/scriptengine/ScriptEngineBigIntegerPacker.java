package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

public class ScriptEngineBigIntegerPacker implements Packer {
    String jsTemplate = null;

    public ScriptEngineBigIntegerPacker() {
        try {
            jsTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/ScriptEngineBigInteger.js")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jsTemplate
                .replace("{{className}}", config.getClassName())
                .replace("{{bigIntegerStr}}", Packers.BigInteger.getInstance().pack(config))
                .replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
