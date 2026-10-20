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
@PackerMeta(name = Packers.JSPX, parent = Packers.JSP, order = 250)
public class JspxPacker implements Packer {

    private final String jspxTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jspx");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jspxTemplate.replace("{{className}}", config.getClassName())
                .replace("\"{{base64Str}}\"", Util.toJavaStringLiteral(config.getClassBytesBase64Str()));
    }
}
