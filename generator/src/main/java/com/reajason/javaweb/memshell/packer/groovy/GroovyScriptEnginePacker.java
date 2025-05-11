package com.reajason.javaweb.memshell.packer.groovy;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class GroovyScriptEnginePacker implements Packer {
    String template = "new javax.script.ScriptEngineManager().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(GenerateResult generateResult) {
        String script = Packers.ScriptEngine.getInstance().pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
