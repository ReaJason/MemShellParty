package com.reajason.javaweb.packer.jar;

import com.reajason.javaweb.asm.ClassAnnotationUtils;
import com.reajason.javaweb.asm.ClassInterfaceUtils;
import com.reajason.javaweb.packer.JarPacker;
import com.reajason.javaweb.packer.JarPackerConfig;
import lombok.SneakyThrows;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * @author ReaJason
 * @since 2025/12/6
 */
public class GroovyTransformJarPacker implements JarPacker {
    @Override
    @SneakyThrows
    public byte[] packBytes(JarPackerConfig config) {
        String mainClassName = config.getMainClassName();
        byte[] mainClassBytes = config.getClassBytes().get(mainClassName);
        mainClassBytes = ClassInterfaceUtils.addInterface(mainClassBytes, "org.codehaus.groovy.transform.ASTTransformation");
        mainClassBytes = ClassAnnotationUtils.setAnnotation(mainClassBytes, "org.codehaus.groovy.transform.GroovyASTTransformation");

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(outputStream, new Manifest())) {
            targetJar.putNextEntry(new JarEntry(mainClassName.replace('.', '/') + ".class"));
            targetJar.write(mainClassBytes);
            targetJar.closeEntry();

            targetJar.putNextEntry(new JarEntry("META-INF/services/org.codehaus.groovy.transform.ASTTransformation"));
            targetJar.write(mainClassName.getBytes(StandardCharsets.UTF_8));
            targetJar.closeEntry();
        }
        return outputStream.toByteArray();
    }
}
