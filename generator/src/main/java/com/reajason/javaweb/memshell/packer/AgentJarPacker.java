package com.reajason.javaweb.memshell.packer;

import com.reajason.javaweb.memshell.config.GenerateResult;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

/**
 * @author ReaJason
 * @since 2025/1/1
 */
public class AgentJarPacker implements JarPacker {

    static Path tempBootPath;

    @Override
    @SneakyThrows
    public byte[] packBytes(GenerateResult generateResult) {
        Path jarPath = Files.createTempFile("temp", ".jar");
        String mainClass = generateResult.getInjectorClassName();
        String advisorClass = generateResult.getShellClassName();

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Agent-Class", mainClass);
        manifest.getMainAttributes().putValue("Premain-Class", mainClass);
        manifest.getMainAttributes().putValue("Can-Redefine-Classes", "true");
        manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");

        try (JarOutputStream targetJar = new JarOutputStream(new FileOutputStream(jarPath.toFile()), manifest)) {
            addDependency(targetJar, ByteBuddy.class);

            if (generateResult.getShellConfig().isJakarta()) {
                addDependency(targetJar, jakarta.servlet.Servlet.class);
            } else {
                addDependency(targetJar, javax.servlet.Servlet.class);
            }

            targetJar.putNextEntry(new JarEntry(mainClass.replace('.', '/') + ".class"));
            targetJar.write(generateResult.getInjectorBytes());
            targetJar.closeEntry();

            targetJar.putNextEntry(new JarEntry(advisorClass.replace('.', '/') + ".class"));
            targetJar.write(generateResult.getShellBytes());
            targetJar.closeEntry();
        }
        byte[] byteArray = IOUtils.toByteArray(new FileInputStream(jarPath.toFile()));
        FileUtils.deleteQuietly(jarPath.toFile());
        return byteArray;
    }

    @SneakyThrows
    public static void addDependency(JarOutputStream targetJar, Class<?> baseClass) {
        String packageToMove = baseClass.getPackage().getName().replace('.', '/');
        URL sourceUrl = baseClass.getProtectionDomain().getCodeSource().getLocation();
        String sourceUrlString = sourceUrl.toString();
        if (sourceUrlString.contains("!BOOT-INF")) {
            String path = sourceUrlString.substring("jar:nested:".length());
            path = path.substring(0, path.indexOf("!/"));
            String[] split = path.split("/!");
            String bootJarPath = split[0];
            String internalJarPath = split[1];
            if (tempBootPath == null) {
                tempBootPath = Files.createTempDirectory("mem-shell-boot");
                unzip(bootJarPath, tempBootPath.toFile().getAbsolutePath());
            }
            sourceUrl = tempBootPath.resolve(internalJarPath).toUri().toURL();
        }
        JarFile sourceJar = new JarFile(new File(sourceUrl.toURI()));
        Enumeration<JarEntry> entries = sourceJar.entries();
        while (entries.hasMoreElements()) {
            JarEntry entry = entries.nextElement();
            String entryName = entry.getName();
            if (entryName.startsWith(packageToMove)) {
                InputStream entryStream = sourceJar.getInputStream(entry);
                targetJar.putNextEntry(new JarEntry(entryName));
                IOUtils.copy(entryStream, targetJar);
                targetJar.closeEntry();
                entryStream.close();
            }
        }
        sourceJar.close();
    }

    @SneakyThrows
    public static void unzip(String jarPath, String tempPath) {
        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry jarEntry = entries.nextElement();
                String entryName = jarEntry.getName();
                File file = new File(tempPath, entryName);
                if (jarEntry.isDirectory()) {
                    file.mkdir();
                } else {
                    InputStream inputStream = null;
                    FileOutputStream outputStream = null;
                    try {
                        inputStream = jarFile.getInputStream(jarEntry);
                        outputStream = new FileOutputStream(file);
                        IOUtils.copy(inputStream, outputStream);
                    } finally {
                        IOUtils.closeQuietly(inputStream);
                        IOUtils.closeQuietly(outputStream);
                    }
                }
            }
        }
    }
}