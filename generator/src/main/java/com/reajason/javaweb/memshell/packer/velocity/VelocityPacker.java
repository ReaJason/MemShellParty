package com.reajason.javaweb.memshell.packer.velocity;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.packer.scriptengine.ScriptEnginePacker;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class VelocityPacker implements Packer {
    ScriptEnginePacker scriptEnginePacker = new ScriptEnginePacker();
    String template = "";

    public VelocityPacker() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/VelocityScriptEngine.txt")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    public String pack(GenerateResult generateResult) {
        String script = scriptEnginePacker.pack(generateResult);
        return template.replace("{{script}}", script);
    }
}