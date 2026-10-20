package com.reajason.javaweb.packer.jar;

import com.reajason.javaweb.asm.ClassInterfaceUtils;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.Packer;
import com.reajason.javaweb.packer.PackerMeta;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import org.kohsuke.MetaInfServices;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * @author ReaJason
 * @since 2025/11/16
 */
@MetaInfServices(Packer.class)
@PackerMeta(name = Packers.ScriptEngineJar, order = 3000)
public class ScriptEngineJarPacker implements JarPacker {

    @Override
    @SneakyThrows
    public byte[] packBytes(JarPackerConfig config) {
        String mainClassName = config.getMainClassName();
        byte[] mainClassBytes = config.getClassBytes().get(mainClassName);
        byte[] bytes = ClassInterfaceUtils.addInterface(mainClassBytes, "javax.script.ScriptEngineFactory");
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(outputStream, new Manifest())) {
            targetJar.putNextEntry(new JarEntry(mainClassName.replace('.', '/') + ".class"));
            targetJar.write(bytes);
            targetJar.closeEntry();

            targetJar.putNextEntry(new JarEntry("META-INF/services/javax.script.ScriptEngineFactory"));
            targetJar.write(mainClassName.getBytes(StandardCharsets.UTF_8));
            targetJar.closeEntry();
        }
        return outputStream.toByteArray();
    }
}
