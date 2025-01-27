package com.reajason.javaweb.memshell.packer.jar;

import com.reajason.javaweb.memshell.config.GenerateResult;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
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
    public byte[] packBytes(GenerateResult generateResult) {
        String mainClass = generateResult.getInjectorClassName().replace('.', '/') + ".class";
        String advisorClass = generateResult.getShellClassName().replace('.', '/') + ".class";

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(byteArrayOutputStream, manifest)) {
            targetJar.putNextEntry(new JarEntry(mainClass));
            targetJar.write(generateResult.getInjectorBytes());
            targetJar.closeEntry();

            targetJar.putNextEntry(new JarEntry(advisorClass));
            targetJar.write(generateResult.getShellBytes());
            targetJar.closeEntry();
        }
        return byteArrayOutputStream.toByteArray();
    }
}
