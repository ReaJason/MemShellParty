package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.spi.ServerProvider;
import com.reajason.javaweb.packer.ClassPackerConfig;
import net.bytebuddy.description.type.TypeDescription;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.StandardLocation;
import javax.tools.ToolProvider;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PluginBootstrapTest {
    @TempDir
    Path tempDir;

    @BeforeEach
    @AfterEach
    void resetRegistries() {
        MemShellRegistry.getInstance().reset();
        PackerRegistry.getInstance().reset();
    }

    @Test
    void resolvesJarSiblingDirectoryAndRelativeOverride() throws Exception {
        Path launchJar = Files.createFile(tempDir.resolve("party.jar"));
        Path base = PluginBootstrap.launchBaseDirectory(
                launchJar.toString(), launchJar + " --server.port=0", tempDir.resolve("cwd").toString());
        assertEquals(tempDir, base);
        assertEquals(tempDir.resolve("plugins"), PluginBootstrap.resolvePluginDirectory(null, base));
        assertEquals(tempDir.resolve("extensions"),
                PluginBootstrap.resolvePluginDirectory("extensions", base));

        Path fallback = tempDir.resolve("cwd");
        assertEquals(fallback, PluginBootstrap.launchBaseDirectory(
                launchJar + File.pathSeparator + tempDir.resolve("other.jar"), launchJar.toString(), fallback.toString()));
        assertEquals(fallback, PluginBootstrap.launchBaseDirectory(
                launchJar.toString(), "org.example.Main", fallback.toString()));
    }

    @Test
    void scansOnlyTopLevelJarsInFileNameOrder() throws Exception {
        Files.createDirectories(tempDir.resolve("nested"));
        Files.write(tempDir.resolve("b.jar"), new byte[0]);
        Files.write(tempDir.resolve("a.JAR"), new byte[0]);
        Files.write(tempDir.resolve("ignored.txt"), new byte[0]);
        Files.write(tempDir.resolve("nested/c.jar"), new byte[0]);
        List<String> warnings = new ArrayList<>();

        List<Path> jars = PluginBootstrap.scanPluginJars(tempDir, warnings);

        assertEquals(Arrays.asList(tempDir.resolve("a.JAR"), tempDir.resolve("b.jar")), jars);
        assertTrue(warnings.isEmpty());
    }

    @Test
    void discoversThreeSpiTypesAndIsolatesDuplicatesAndBrokenProvider() throws Exception {
        createMalformedPluginJar();
        createPluginJar("a.jar", "fixture.a", "First", true);
        createPluginJar("b.jar", "fixture.b", "Second", false);
        ClassLoader original = Thread.currentThread().getContextClassLoader();

        PluginLoadResult result = PluginBootstrap.load(tempDir, getClass().getClassLoader());

        assertSame(original, Thread.currentThread().getContextClassLoader());
        assertEquals(2, result.getPluginJars().size());
        assertTrue(MemShellRegistry.getInstance().getSupportedServers().contains("SharedServer"));
        assertTrue(MemShellRegistry.getInstance().getSupportedTools().contains("SharedTool"));
        assertTrue(MemShellRegistry.getInstance().getServer("SharedServer").getClass().getName()
                .startsWith("fixture.a.FirstServerProvider"));
        assertEquals("fixture.a.FirstToolProvider",
                MemShellRegistry.getInstance().getToolProvider("SharedTool").getClass().getName());
        assertEquals("first", PackerRegistry.getInstance().get("SharedPacker")
                .pack(ClassPackerConfig.of("example.Payload", new byte[]{1}, "AQ==", false)));
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("0-bad.jar")),
                "坏 jar 应被隔离: " + result.getWarnings());
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("broken-fixture")),
                "坏 provider 应产生诊断: " + result.getWarnings());
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("broken-server-fixture")));
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("broken-tool-fixture")));
        assertFalse(MemShellRegistry.getInstance().getSupportedServers().contains("BrokenServer"));
        assertFalse(MemShellRegistry.getInstance().getSupportedTools().contains("BrokenTool"));
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("Server 重名: SharedServer")));
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("ShellTool 重名: SharedTool")));
        assertTrue(result.getWarnings().stream().anyMatch(message -> message.contains("Packer 重名: SharedPacker")));
    }

    private void createMalformedPluginJar() throws IOException {
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(tempDir.resolve("0-bad.jar")))) {
            output.putNextEntry(new JarEntry("META-INF/services/com.reajason.javaweb.packer.Packer"));
            output.write("not a class name\n".getBytes(StandardCharsets.UTF_8));
            output.closeEntry();
        }
    }

    private void createPluginJar(String jarName, String packageName, String prefix, boolean broken) throws Exception {
        Path sourceRoot = tempDir.resolve(jarName + "-src");
        Path classes = tempDir.resolve(jarName + "-classes");
        Files.createDirectories(sourceRoot);
        Files.createDirectories(classes);
        List<File> sources = new ArrayList<>();
        String packagePath = packageName.replace('.', '/');
        sources.add(writeSource(sourceRoot, packagePath, prefix + "ServerProvider", serverSource(packageName, prefix)));
        sources.add(writeSource(sourceRoot, packagePath, prefix + "ToolProvider", toolSource(packageName, prefix)));
        sources.add(writeSource(sourceRoot, packagePath, prefix + "Packer", packerSource(packageName, prefix, "first".equalsIgnoreCase(prefix) ? "first" : "second")));
        if (broken) {
            sources.add(writeSource(sourceRoot, packagePath, "BrokenServerProvider", brokenServerSource(packageName)));
            sources.add(writeSource(sourceRoot, packagePath, "BrokenToolProvider", brokenToolSource(packageName)));
            sources.add(writeSource(sourceRoot, packagePath, "BrokenPacker", brokenPackerSource(packageName)));
        }
        compile(sources, classes);

        Path jar = tempDir.resolve(jarName);
        try (JarOutputStream output = new JarOutputStream(Files.newOutputStream(jar))) {
            try (Stream<Path> paths = Files.walk(classes)) {
                for (Path classFile : (Iterable<Path>) paths.filter(Files::isRegularFile)::iterator) {
                    String entryName = classes.relativize(classFile).toString().replace(File.separatorChar, '/');
                    output.putNextEntry(new JarEntry(entryName));
                    output.write(Files.readAllBytes(classFile));
                    output.closeEntry();
                }
            }
            String servers = packageName + "." + prefix + "ServerProvider"
                    + (broken ? "\n" + packageName + ".BrokenServerProvider" : "");
            addService(output, "com.reajason.javaweb.memshell.spi.ServerProvider", servers);
            String tools = packageName + "." + prefix + "ToolProvider"
                    + (broken ? "\n" + packageName + ".BrokenToolProvider" : "");
            addService(output, "com.reajason.javaweb.memshell.spi.ShellToolProvider", tools);
            String packers = packageName + "." + prefix + "Packer" + (broken ? "\n" + packageName + ".BrokenPacker" : "");
            addService(output, "com.reajason.javaweb.packer.Packer", packers);
        }
    }

    private static File writeSource(Path root, String packagePath, String className, String content) throws IOException {
        Path source = root.resolve(packagePath).resolve(className + ".java");
        Files.createDirectories(source.getParent());
        Files.write(source, content.getBytes(StandardCharsets.UTF_8));
        return source.toFile();
    }

    private static void compile(List<File> sources, Path classes) throws Exception {
        JavaCompiler compiler = ToolProvider.getSystemJavaCompiler();
        if (compiler == null) {
            throw new IllegalStateException("Tests require a JDK");
        }
        try (StandardJavaFileManager files = compiler.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            files.setLocation(StandardLocation.CLASS_OUTPUT, Collections.singleton(classes.toFile()));
            String classPath = String.join(File.pathSeparator, Arrays.asList(
                    codeSource(ServerProvider.class), codeSource(MemShellRegistry.class),
                    codeSource(com.reajason.javaweb.utils.NameSampler.class), codeSource(TypeDescription.class)));
            List<String> options = Arrays.asList("-classpath", classPath, "-source", "8", "-target", "8");
            boolean success = compiler.getTask(null, files, null, options, null,
                    files.getJavaFileObjectsFromFiles(sources)).call();
            assertTrue(success, "fixture compilation failed");
        }
    }

    private static String codeSource(Class<?> type) throws URISyntaxException {
        return Paths.get(type.getProtectionDomain().getCodeSource().getLocation().toURI()).toString();
    }

    private static void addService(JarOutputStream output, String service, String implementation) throws IOException {
        output.putNextEntry(new JarEntry("META-INF/services/" + service));
        output.write((implementation + "\n").getBytes(StandardCharsets.UTF_8));
        output.closeEntry();
    }

    private static String serverSource(String packageName, String prefix) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.memshell.server.*;\n"
                + "import com.reajason.javaweb.memshell.spi.*;\n"
                + "@ServerMeta(name=\"SharedServer\")\n"
                + "public class " + prefix + "ServerProvider implements ServerProvider {\n"
                + "  public AbstractServer createServer() { return new AbstractServer() {\n"
                + "    public InjectorMapping getShellInjectorMapping() { return InjectorMapping.builder().build(); }\n"
                + "  }; }\n"
                + "}\n";
    }

    private static String toolSource(String packageName, String prefix) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.ShellGenerator;\n"
                + "import com.reajason.javaweb.memshell.config.ShellToolConfig;\n"
                + "import com.reajason.javaweb.memshell.server.ToolMapping;\n"
                + "import com.reajason.javaweb.memshell.spi.*;\n"
                + "@ShellToolMeta(name=\"SharedTool\")\n"
                + "public class " + prefix + "ToolProvider implements ShellToolProvider {\n"
                + "  public ToolMapping getToolMapping() { return ToolMapping.builder().build(); }\n"
                + "  public Class<? extends ShellToolConfig> getConfigClass() { return null; }\n"
                + "  public Class<? extends ShellGenerator> getGeneratorClass() { return null; }\n"
                + "}\n";
    }

    private static String packerSource(String packageName, String prefix, String value) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.packer.*;\n"
                + "@PackerMeta(name=\"SharedPacker\")\n"
                + "public class " + prefix + "Packer implements Packer {\n"
                + "  public String pack(ClassPackerConfig config) { return \"" + value + "\"; }\n"
                + "}\n";
    }

    private static String brokenServerSource(String packageName) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.memshell.server.AbstractServer;\n"
                + "import com.reajason.javaweb.memshell.spi.*;\n"
                + "@ServerMeta(name=\"BrokenServer\")\n"
                + "public class BrokenServerProvider implements ServerProvider {\n"
                + "  public AbstractServer createServer() { throw new IllegalStateException(\"broken-server-fixture\"); }\n"
                + "}\n";
    }

    private static String brokenToolSource(String packageName) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.ShellGenerator;\n"
                + "import com.reajason.javaweb.memshell.config.ShellToolConfig;\n"
                + "import com.reajason.javaweb.memshell.server.ToolMapping;\n"
                + "import com.reajason.javaweb.memshell.spi.*;\n"
                + "@ShellToolMeta(name=\"BrokenTool\")\n"
                + "public class BrokenToolProvider implements ShellToolProvider {\n"
                + "  public ToolMapping getToolMapping() { throw new IllegalStateException(\"broken-tool-fixture\"); }\n"
                + "  public Class<? extends ShellToolConfig> getConfigClass() { return null; }\n"
                + "  public Class<? extends ShellGenerator> getGeneratorClass() { return null; }\n"
                + "}\n";
    }

    private static String brokenPackerSource(String packageName) {
        return "package " + packageName + ";\n"
                + "import com.reajason.javaweb.packer.*;\n"
                + "@PackerMeta(name=\"BrokenPacker\")\n"
                + "public class BrokenPacker implements Packer {\n"
                + "  public BrokenPacker() { throw new IllegalStateException(\"broken-fixture\"); }\n"
                + "  public String pack(ClassPackerConfig config) { return \"broken\"; }\n"
                + "}\n";
    }
}
