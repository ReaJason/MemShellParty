package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class JspxPacker implements Packer {

    private final String jspxTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jspx");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jspxTemplate.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}