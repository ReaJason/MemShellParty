package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.config.GenerateResult;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class FreemarkerPacker implements Packer {
    ScriptEnginePacker scriptEnginePacker = new ScriptEnginePacker();
    String template = "";

    public FreemarkerPacker() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/FreemarkerScriptEngine.txt")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    public String pack(GenerateResult generateResult) {
        String script = scriptEnginePacker.pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
