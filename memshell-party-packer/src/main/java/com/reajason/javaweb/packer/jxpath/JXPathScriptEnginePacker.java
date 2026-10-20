package com.reajason.javaweb.packer.jxpath;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.scriptengine.ScriptEngineNoSquareBracketsPacker;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.JXPathScriptEngine, parent = Packers.JXPath, order = 1210)
public class JXPathScriptEnginePacker implements Packer {
    String template = "eval(getEngineByName(javax.script.ScriptEngineManager.new(), 'js'), '{{script}}')";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEngineNoSquareBracketsPacker().pack(config);
        return template.replace("{{script}}", script);
    }
}
