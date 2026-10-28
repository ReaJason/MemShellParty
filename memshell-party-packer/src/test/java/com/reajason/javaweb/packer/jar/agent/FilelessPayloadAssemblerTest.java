package com.reajason.javaweb.packer.jar.agent;

import com.reajason.javaweb.fileless.FilelessAgentBootstrap;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.io.IOException;
import java.net.JarURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarOutputStream;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FilelessPayloadAssemblerTest {
    private static final String RUNTIME_PACKAGE = "com.reajason.javaweb.fileless";
    private static final String RUNTIME_PACKAGE_PATH = RUNTIME_PACKAGE.replace('.', '/');

    @Test
    void readsRuntimeClassesFromNestedJarLocation(@TempDir Path tempDir) throws Exception {
        Path runtimeJar = tempDir.resolve("memshell-party-fileless.jar");
        writeRuntimeJar(runtimeJar);
        URL jarFileUrl = runtimeJar.toUri().toURL();
        URLStreamHandler nestedHandler = new URLStreamHandler() {
            @Override
            protected URLConnection openConnection(URL url) throws IOException {
                return new JarURLConnection(url) {
                    @Override
                    public void connect() {
                    }

                    @Override
                    public JarFile getJarFile() throws IOException {
                        return new JarFile(runtimeJar.toFile());
                    }

                    @Override
                    public URL getJarFileURL() {
                        return jarFileUrl;
                    }
                };
            }
        };
        URL location = new URL(null, "jar:" + jarFileUrl
                + "/!BOOT-INF/lib/" + runtimeJar.getFileName() + "!/", nestedHandler);

        Map<String, byte[]> classes = FilelessPayloadAssembler.readRuntimeClasses(location);

        assertEquals(RUNTIME_PACKAGE + ".InstrumentationProvider", classes.keySet().iterator().next());
        assertTrue(classes.containsKey(RUNTIME_PACKAGE + ".JarLoader"));
        assertTrue(classes.containsKey(RUNTIME_PACKAGE + ".JarLoader$MemoryURLConnection"));
        assertTrue(classes.containsKey(RUNTIME_PACKAGE + ".JarLoader$MemoryURLStreamHandler"));
    }

    private static void writeRuntimeJar(Path runtimeJar) throws Exception {
        URL location = FilelessAgentBootstrap.class.getProtectionDomain().getCodeSource().getLocation();
        Path source = Paths.get(location.toURI());
        if (Files.isRegularFile(source)) {
            Files.copy(source, runtimeJar);
            return;
        }
        Path packageRoot = source.resolve(RUNTIME_PACKAGE_PATH);
        List<Path> files;
        try (Stream<Path> paths = Files.walk(packageRoot)) {
            files = paths.filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().endsWith(".class"))
                    .collect(Collectors.toList());
        }
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(runtimeJar))) {
            for (Path file : files) {
                String relative = packageRoot.relativize(file).toString().replace(File.separatorChar, '/');
                output.putNextEntry(new JarEntry(RUNTIME_PACKAGE_PATH + "/" + relative));
                output.write(Files.readAllBytes(file));
                output.closeEntry();
            }
        }
    }
}
