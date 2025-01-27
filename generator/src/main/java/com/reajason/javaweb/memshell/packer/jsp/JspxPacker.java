package com.reajason.javaweb.memshell.packer.jsp;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
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
    public String pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        return jspxTemplate.replace("{{className}}", injectorClassName).replace("{{base64Str}}", injectorBytesBase64Str);
    }
}