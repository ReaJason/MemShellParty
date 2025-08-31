package com.reajason.javaweb.packer.jar;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.packer.JarPackerConfig;
import com.reajason.javaweb.packer.jar.attach.Attacher;
import com.reajason.javaweb.packer.jar.attach.VirtualMachine;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.objectweb.asm.Opcodes;
import org.objectweb.asm.commons.Remapper;
import org.objectweb.asm.tree.ClassNode;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;
import java.util.jar.*;

/**
 * @author ReaJason
 * @since 2025/1/1
 */
public class AgentJarWithJDKAttacherPacker implements JarPacker {
    private static Path tempBootPath;

    @Override
    @SneakyThrows
    public byte[] packBytes(JarPackerConfig jarPackerConfig) {
        String packageName = getPackageName(jarPackerConfig.getMainClassName());
        String mainClassName = packageName + "." + Attacher.class.getSimpleName();
        Manifest manifest = createManifest(jarPackerConfig.getMainClassName(), mainClassName);
        String relocatePrefix = "shade/";

        Map<String, byte[]> classes = new HashMap<>();
        Map<String, byte[]> attacherClasses = com.reajason.javaweb.buddy.ClassRenameUtils.renamePackage(Attacher.class, packageName);
        Map<String, byte[]> virtualMachineClasses = com.reajason.javaweb.buddy.ClassRenameUtils.renamePackage(VirtualMachine.class, packageName);
        classes.putAll(attacherClasses);
        classes.putAll(virtualMachineClasses);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(outputStream, manifest)) {
            addAsmDependencies(targetJar, relocatePrefix);
            addClassesToJar(targetJar, jarPackerConfig.getClassBytes(), relocatePrefix);
            for (Map.Entry<String, byte[]> entry : classes.entrySet()) {
                String className = entry.getKey();
                byte[] bytes = entry.getValue();
                targetJar.putNextEntry(new JarEntry(className.replace('.', '/') + ".class"));
                targetJar.write(ClassBytesShrink.shrink(bytes, true));
                targetJar.closeEntry();
            }
        }
        return outputStream.toByteArray();
    }

    private Manifest createManifest(String agentClass, String mainClass) {
        Manifest manifest = new Manifest();
        Attributes attributes = manifest.getMainAttributes();
        attributes.putValue("Manifest-Version", "1.0");
        attributes.putValue("Agent-Class", agentClass);
        attributes.putValue("Premain-Class", agentClass);
        attributes.putValue("Main-Class", mainClass);
        attributes.putValue("Can-Redefine-Classes", "true");
        attributes.putValue("Can-Retransform-Classes", "true");
        return manifest;
    }

    @SneakyThrows
    private void addAsmDependencies(JarOutputStream targetJar, String relocatePrefix) {
        String baseName = Opcodes.class.getPackage().getName().replace('.', '/');
        String commonBaseName = Remapper.class.getPackage().getName().replace('.', '/');
        String treeBaseName = ClassNode.class.getPackage().getName().replace('.', '/');
        URL sourceUrl = Opcodes.class.getProtectionDomain().getCodeSource().getLocation();
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
        try (JarFile sourceJar = new JarFile(new File(sourceUrl.toURI()))) {
            Enumeration<JarEntry> entries = sourceJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (entryName.equals("META-INF/MANIFEST.MF")
                        || entryName.contains("module-info.class")
                        || !entryName.startsWith(baseName)
                        || entryName.startsWith(commonBaseName)
                        || entryName.startsWith(treeBaseName)) {
                    continue;
                }
                if (!entry.isDirectory()) {
                    try (InputStream entryStream = sourceJar.getInputStream(entry)) {
                        byte[] bytes = IOUtils.toByteArray(entryStream);
                        if (StringUtils.isNoneEmpty(relocatePrefix)) {
                            targetJar.putNextEntry(new JarEntry(relocatePrefix + entryName));
                            if (entryName.endsWith(".class")) {
                                if (bytes.length > 0) {
                                    bytes = ClassBytesShrink.shrink(ClassRenameUtils.relocateClass(bytes, baseName, relocatePrefix + baseName), true);
                                }
                            } else {
                                targetJar.putNextEntry(entry);
                            }
                        } else {
                            targetJar.putNextEntry(entry);
                        }
                        targetJar.write(bytes);
                    }
                }
                targetJar.closeEntry();
            }
        }
    }

    @SneakyThrows
    private void addClassesToJar(JarOutputStream targetJar, Map<String, byte[]> bytes, String relocatePrefix) {
        String dependencyPackage = Opcodes.class.getPackage().getName();
        for (Map.Entry<String, byte[]> entry : bytes.entrySet()) {
            String className = entry.getKey();
            byte[] classBytes = entry.getValue();
            targetJar.putNextEntry(new JarEntry(className.replace('.', '/') + ".class"));
            byte[] processedBytes = ClassBytesShrink.shrink(ClassRenameUtils.relocateClass(classBytes, dependencyPackage, relocatePrefix + dependencyPackage), true);
            targetJar.write(processedBytes);
            targetJar.closeEntry();
        }
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