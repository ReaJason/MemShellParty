package com.reajason.javaweb.packer.bsh;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/1/30
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.BeanShell, order = 1400)
public class BeanShellPacker implements Packer {
    String template = "new javax.script.ScriptEngineManager().getEngineByName(\"js\").eval(\"{{script}}\")";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEnginePacker().pack(config);
        return template.replace("{{script}}", script.replaceAll("\\\"", "'"));
    }
}
