package com.reajason.javaweb.packer.groovy;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/5/11
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.GroovyClassDefiner, parent = Packers.Groovy, order = 1610)
public class GroovyClassDefinerPacker implements Packer {
    private final String template = Util.loadTemplateFromResource("/memshell-party/shell.groovy");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("'{{base64Str}}'", Util.toSingleQuotedConcatLiteral(config.getClassBytesBase64Str()));
    }
}
