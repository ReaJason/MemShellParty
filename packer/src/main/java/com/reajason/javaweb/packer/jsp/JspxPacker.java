package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;

import java.nio.charset.Charset;
import java.util.Objects;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class JspxPacker implements Packer {

    String jspxTemplate = null;

    public JspxPacker() {
        try {
            jspxTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell.jspx")), Charset.defaultCharset());
        } catch (Exception ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return jspxTemplate.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}