package com.reajason.javaweb.fileless;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.jar.Manifest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class FilelessAgentRealInstrumentationTest {

    @TempDir
    Path tempDir;

    @Test
    void installsThroughRealInstrumentationAndRetransformsLoadedClass() throws Exception {
        File agentJar = tempDir.resolve("fixture-agent.jar").toFile();
        writeStarterAgent(agentJar);
        String javaExecutable = new File(new File(System.getProperty("java.home"), "bin"),
                isWindows() ? "java.exe" : "java").getAbsolutePath();
        Process process = new ProcessBuilder(
                javaExecutable,
                "-javaagent:" + agentJar.getAbsolutePath(),
                "-cp", System.getProperty("java.class.path"),
                RealAgentFixture.class.getName())
                .redirectErrorStream(true)
                .start();
        String output = readProcessOutput(process);
        int exitCode = process.waitFor();

        assertEquals(0, exitCode, output);
    }

    private static void writeStarterAgent(File agentJar) throws Exception {
        Manifest manifest = new Manifest();
        manifest.getMainAttributes().putValue("Manifest-Version", "1.0");
        manifest.getMainAttributes().putValue("Premain-Class", RealAgentFixture.Starter.class.getName());
        manifest.getMainAttributes().putValue("Can-Redefine-Classes", "true");
        manifest.getMainAttributes().putValue("Can-Retransform-Classes", "true");
        JarOutputStream output = new JarOutputStream(new FileOutputStream(agentJar), manifest);
        try {
            String entryName = RealAgentFixture.Starter.class.getName().replace('.', '/') + ".class";
            output.putNextEntry(new JarEntry(entryName));
            InputStream input = RealAgentFixture.class.getClassLoader().getResourceAsStream(entryName);
            try {
                copy(input, output);
            } finally {
                input.close();
            }
            output.closeEntry();
        } finally {
            output.close();
        }
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
