package com.reajason.javaweb.memsell.packer;

import com.reajason.javaweb.config.GenerateResult;
import org.apache.commons.io.IOUtils;

import java.io.IOException;
import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class OgnlPacker implements Packer {
    ScriptEnginePacker scriptEnginePacker = new ScriptEnginePacker();
    String template = "";

    public OgnlPacker() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/OgnlScriptEngine.txt")), Charset.defaultCharset());
        } catch (IOException ignored) {

        }
    }

    @Override
    public byte[] pack(GenerateResult generateResult) {
        byte[] scriptBytes = scriptEnginePacker.pack(generateResult);
        return template.replace("{{script}}", new String(scriptBytes)).getBytes();
    }
}
