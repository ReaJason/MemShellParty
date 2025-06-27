package com.reajason.javaweb.packer.jar;

import com.reajason.javaweb.packer.JarPackerConfig;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * @author ReaJason
 * @since 2025/1/22
 */
public class DefaultJarPacker implements JarPacker {

    @Override
    @SneakyThrows
    public byte[] packBytes(JarPackerConfig jarPackerConfig) {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(byteArrayOutputStream, manifest)) {
            for (Map.Entry<String, byte[]> entry : jarPackerConfig.getClassBytes().entrySet()) {
                targetJar.putNextEntry(new JarEntry(entry.getKey().replace('.', '/') + ".class"));
                targetJar.write(entry.getValue());
                targetJar.closeEntry();
            }
        }
        return byteArrayOutputStream.toByteArray();
    }
}
