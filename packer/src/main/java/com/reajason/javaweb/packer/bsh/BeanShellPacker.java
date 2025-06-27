package com.reajason.javaweb.packer.bsh;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
public class BeanShellPacker implements Packer {
    String template = "new javax.script.ScriptEngineManager().getEngineByName(\"js\").eval(\"{{script}}\")";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        return template.replace("{{script}}", script.replaceAll("\\\"", "'"));
    }
}
