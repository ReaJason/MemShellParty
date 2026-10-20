package com.reajason.javaweb.packer.scriptengine;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.DefaultScriptEngine, parent = Packers.ScriptEngine, order = 610)
public class DefaultScriptEnginePacker implements Packer {
    private final String jsTemplate = Util.loadTemplateFromResource("/memshell-party/ScriptEngine.js");
    private final String jsBypassModuleTemplate = Util.loadTemplateFromResource("/memshell-party/ScriptEngineBypassModule.js");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        String template = jsTemplate;
        if (config.isByPassJavaModule()) {
            template = jsBypassModuleTemplate;
        }
        return scriptToSingleLine(template
                .replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str()));
    }

    public static String scriptToSingleLine(String script) {
        return script.replace("\n", "")
                .replaceAll("(?m)^[ \t]+|[ \t]+$", "")
                .replaceAll("[ \t]{2,}", " ");
    }
}
