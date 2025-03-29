package com.reajason.javaweb.memshell.packer.jar;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.ShellType;
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
import java.util.jar.*;

/**
 * @author ReaJason
 * @since 2025/1/1
 */
public class AgentJarPacker implements JarPacker {
    private static Path tempBootPath;

    @Override
    @SneakyThrows
    public byte[] packBytes(GenerateResult generateResult) {
        Manifest manifest = createManifest(generateResult.getInjectorClassName());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        String relocatePrefix = CommonUtil.getRandomPackageName().replace(".", "/") + "/";
        boolean isAsm = generateResult.getShellConfig().getShellType().endsWith(ShellType.ASM);

        try (JarOutputStream targetJar = new JarOutputStream(outputStream, manifest)) {
            addDependencies(targetJar, relocatePrefix, isAsm);
            addClassesToJar(targetJar, generateResult, relocatePrefix, isAsm);
        }

        return outputStream.toByteArray();
    }

    private Manifest createManifest(String mainClass) {
        Manifest manifest = new Manifest();
        Attributes attributes = manifest.getMainAttributes();
        attributes.putValue("Manifest-Version", "1.0");
        attributes.putValue("Agent-Class", mainClass);
        attributes.putValue("Premain-Class", mainClass);
        attributes.putValue("Can-Redefine-Classes", "true");
        attributes.putValue("Can-Retransform-Classes", "true");
        return manifest;
    }

    @SneakyThrows
    private void addDependencies(JarOutputStream targetJar, String relocatePrefix, boolean isAsm) {
        if (isAsm) {
            addDependency(targetJar, Opcodes.class, true, relocatePrefix);
        } else {
            addDependency(targetJar, ByteBuddy.class, false, relocatePrefix);
        }
    }

    @SneakyThrows
    private void addClassesToJar(JarOutputStream targetJar, GenerateResult generateResult,
                                 String relocatePrefix, boolean isRelocateEnabled) {
        String dependencyPackage = isRelocateEnabled ?
                Opcodes.class.getPackage().getName() : ByteBuddy.class.getPackage().getName();

        // Add injector class
        addClassEntry(targetJar,
                generateResult.getInjectorClassName(),
                generateResult.getInjectorBytes(),
                dependencyPackage,
                relocatePrefix,
                isRelocateEnabled);

        // Add shell class
        addClassEntry(targetJar,
                generateResult.getShellClassName(),
                generateResult.getShellBytes(),
                dependencyPackage,
                relocatePrefix,
                isRelocateEnabled);

        // Add inner classes
        for (Map.Entry<String, byte[]> entry : generateResult.getInjectorInnerClassBytes().entrySet()) {
            addClassEntry(targetJar,
                    entry.getKey(),
                    entry.getValue(),
                    dependencyPackage,
                    relocatePrefix,
                    isRelocateEnabled);
        }
    }

    @SneakyThrows
    private void addClassEntry(JarOutputStream targetJar, String className, byte[] classBytes,
                               String dependencyPackage, String relocatePrefix, boolean isRelocateEnabled) {
        targetJar.putNextEntry(new JarEntry(className.replace('.', '/') + ".class"));
        byte[] processedBytes = isRelocateEnabled ?
                ClassRenameUtils.relocateClass(classBytes, dependencyPackage, relocatePrefix + dependencyPackage) :
                classBytes;
        targetJar.write(processedBytes);
        targetJar.closeEntry();
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

    /**
     * Extracts a JAR file to a temporary directory
     *
     * @param jarPath  Path to the source JAR file
     * @param tempPath Path to the temporary directory
     */
    @SneakyThrows
    public static void unzip(String jarPath, String tempPath) {
        try (JarFile jarFile = new JarFile(jarPath)) {
            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry jarEntry = entries.nextElement();
                File targetFile = new File(tempPath, jarEntry.getName());

                if (jarEntry.isDirectory()) {
                    targetFile.mkdirs();
                    continue;
                }

                targetFile.getParentFile().mkdirs();
                try (InputStream inputStream = jarFile.getInputStream(jarEntry);
                     FileOutputStream outputStream = new FileOutputStream(targetFile)) {
                    IOUtils.copy(inputStream, outputStream);
                }
            }
        }
    }
}