package com.reajason.javaweb.packer.h2;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2025/6/28
 */
public class H2JSPacker implements Packer {
    String template = "jdbc:h2:mem:a;init=CREATE TRIGGER a BEFORE SELECT ON INFORMATION_SCHEMA.TABLES AS $$//javascript\n{{script}}$$";

    @Override
    public String pack(ClassPackerConfig config) {
        String script = Packers.ScriptEngine.getInstance().pack(config);
        return template.replace("{{script}}", script.replaceAll(";", "\\\\;"));
    }
}
