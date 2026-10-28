package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FilelessAgentRealJarInstrumentationTest {

    @Test
    void realInstrumentationRetransformsClassesLoadedOnlyFromMemoryJar() throws Exception {
        Path verificationDirectory = Paths.get("build", "verification");
        Files.createDirectories(verificationDirectory);
        File applicationJar = verificationDirectory.resolve("real-fileless-fixture.jar").toFile();
        writeApplicationJar(applicationJar);
        String javaExecutable = new File(new File(System.getProperty("java.home"), "bin"),
                isWindows() ? "java.exe" : "java").getAbsolutePath();
        Process process = new ProcessBuilder(
                javaExecutable,
                "-javaagent:" + applicationJar.getAbsolutePath(),
                "-jar", applicationJar.getAbsolutePath())
                .redirectErrorStream(true)
                .start();
        String output = readProcessOutput(process);
        int exitCode = process.waitFor();

        assertEquals(0, exitCode, output);
    }

    private static void writeApplicationJar(File file) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", RealJarAgentFixture.Starter.class.getName());
        manifest.getMainAttributes().putValue("Main-Class", RealJarAgentFixture.class.getName());
        manifest.getMainAttributes().putValue("Can-Redefine-Classes", "true");
        manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
        JarOutputStream output = new JarOutputStream(new FileOutputStream(file), manifest);
        try {
            addClass(output, RealJarAgentFixture.class);
            addClass(output, RealJarAgentFixture.Starter.class);
            addRuntime(output);
            addEntry(output, "target-agent.jar", targetAgentJar());
        } finally {
            output.close();
        }
    }

    private static void addRuntime(JarOutputStream output) throws Exception {
        Class<?>[] runtimeClasses = new Class<?>[]{
                FilelessAgentBootstrap.class,
                JarLoader.class,
                InstrumentationProvider.class,
                RuntimeFingerprint.class,
                Elf64File.class,
                NativeImage.class,
                X86_64JPLISLayout.class,
                X86_64StrippedJPLIS.class,
                AArch64JPLISLayout.class,
                LinuxAcquisitionResolver.class,
                LinuxInstrumentationProvider.class,
                X86_64NativeStub.class,
                AArch64NativeStub.class,
                HotSpotProfileProvider.class
        };
        for (Class<?> runtimeClass : runtimeClasses) {
            addClass(output, runtimeClass);
        }
        ClassLoader loader = FilelessAgentRealJarInstrumentationTest.class.getClassLoader();
        addClass(output, Class.forName(JarLoader.class.getName() + "$MemoryURLStreamHandler", false, loader));
        addClass(output, Class.forName(JarLoader.class.getName() + "$MemoryURLConnection", false, loader));
    }

    private static byte[] targetAgentJar() throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Agent-Class", RealJarAgentFixture.RealJarTargetAgent.class.getName());
        manifest.getMainAttributes().putValue("Fileless-Agent-Contract", "1");
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        JarOutputStream output = new JarOutputStream(bytes, manifest);
        try {
            addClass(output, RealJarAgentFixture.RealJarTargetAgent.class);
            addClass(output, RealJarAgentFixture.RealJarTargetTransformer.class);
            addClass(output, RealJarAgentFixture.RealJarTarget.class);
            addClass(output, RetransformFixture.class);
        } finally {
            output.close();
        }
        return bytes.toByteArray();
    }

    private static void addClass(JarOutputStream output, Class<?> type) throws Exception {
        String entryName = type.getName().replace('.', '/') + ".class";
        InputStream input = type.getClassLoader().getResourceAsStream(entryName);
        if (input == null) {
            throw new IllegalStateException("Missing " + entryName);
        }
        try {
            ByteArrayOutputStream classBytes = new ByteArrayOutputStream();
            copy(input, classBytes);
            byte[] bytes = classBytes.toByteArray();
            int classFileVersion = ((bytes[6] & 0xff) << 8) | (bytes[7] & 0xff);
            assertEquals(50, classFileVersion, entryName + " must be loadable by JRE 6");
            output.putNextEntry(new JarEntry(entryName));
            output.write(bytes);
            output.closeEntry();
        } finally {
            input.close();
        }
    }

    private static void addEntry(JarOutputStream output, String name, byte[] bytes) throws Exception {
        output.putNextEntry(new JarEntry(name));
        output.write(bytes);
        output.closeEntry();
    }

    private static String readProcessOutput(Process process) throws Exception {
        InputStream input = process.getInputStream();
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            copy(input, output);
            return new String(output.toByteArray(), "UTF-8");
        } finally {
            input.close();
        }
    }

    private static void copy(InputStream input, java.io.OutputStream output) throws Exception {
        byte[] buffer = new byte[4096];
        int length;
        while ((length = input.read(buffer)) != -1) {
            output.write(buffer, 0, length);
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }
}
