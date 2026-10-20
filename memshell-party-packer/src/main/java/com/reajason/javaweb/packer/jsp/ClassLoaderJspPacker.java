package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.ClassLoaderJSP, parent = Packers.JSP, order = 210)
public class ClassLoaderJspPacker implements Packer {

    private final String jspTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jsp");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jspTemplate.replace("{{className}}", config.getClassName())
                .replace("\"{{base64Str}}\"", Util.toJavaStringLiteral(config.getClassBytesBase64Str()));
    }
}
