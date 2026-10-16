package com.reajason.javaweb.packer.jxpath;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class JXPathScriptEnginePacker implements Packer {
    String template = "eval(getEngineByName(javax.script.ScriptEngineManager.new(), 'js'), '{{script}}')";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngineNoSquareBrackets.getInstance().pack(config);
        return template.replace("{{script}}", script);
    }
}
