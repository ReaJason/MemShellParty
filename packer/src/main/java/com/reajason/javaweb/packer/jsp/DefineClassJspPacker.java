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
    public String pack(ClassPackerConfig config) {
        String injectorBytesBase64Str = config.getClassBytesBase64Str();
        String injectorClassName = config.getClassName();
        String template = this.template;
        if (config.isByPassJavaModule()) {
            template = bypassTemplate;
        }
        return template.replace("{{className}}", injectorClassName)
                .replace("{{base64Str}}", injectorBytesBase64Str);
    }
}