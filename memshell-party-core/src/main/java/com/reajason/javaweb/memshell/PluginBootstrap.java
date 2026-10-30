package com.reajason.javaweb.memshell;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

/**
 * boot 与桌面发行版共用的启动期插件入口。只装载三类核心 SPI，不接管宿主的其他 SPI。
 */
public final class PluginBootstrap {
    public static final String DIRECTORY_PROPERTY = "memshell.plugins.dir";
    public static final String DIRECTORY_ENV = "MEMSHELL_PLUGINS_DIR";

    private static final String[] SPI_SERVICES = {
            "com.reajason.javaweb.memshell.spi.ServerProvider",
            "com.reajason.javaweb.memshell.spi.ShellToolProvider",
            "com.reajason.javaweb.packer.Packer"
    };

    private PluginBootstrap() {
    }

    /**
     * 必须在首次访问两个核心注册表之前调用。新增、更新或删除插件均需重启。
     */
    public static PluginLoadResult load() {
        String configured = System.getProperty(DIRECTORY_PROPERTY);
        if (isBlank(configured)) {
            configured = System.getenv(DIRECTORY_ENV);
        }
        Path baseDirectory = launchBaseDirectory(
                System.getProperty("java.class.path"),
                System.getProperty("sun.java.command"),
                System.getProperty("user.dir"));
        return load(resolvePluginDirectory(configured, baseDirectory), Thread.currentThread().getContextClassLoader());
    }

    static PluginLoadResult load(Path directory, ClassLoader parentLoader) {
        Path normalizedDirectory = directory.toAbsolutePath().normalize();
        List<String> warnings = new ArrayList<>();
        List<Path> scannedJars = scanPluginJars(normalizedDirectory, warnings);
        List<URL> urls = new ArrayList<>(scannedJars.size());
        List<Path> loadedJars = new ArrayList<>(scannedJars.size());
        for (Path jar : scannedJars) {
            if (!hasValidServiceDescriptors(jar, warnings)) {
                continue;
            }
            try {
                urls.add(jar.toUri().toURL());
                loadedJars.add(jar);
            } catch (MalformedURLException e) {
                warnings.add("插件路径无效: " + jar + ": " + SpiLoader.message(e));
            }
        }

        ClassLoader effectiveParent = parentLoader != null ? parentLoader : PluginBootstrap.class.getClassLoader();
        ClassLoader pluginLoader = urls.isEmpty() ? effectiveParent
                : new PluginClassLoader(urls.toArray(new URL[0]), effectiveParent);
        Thread thread = Thread.currentThread();
        ClassLoader originalLoader = thread.getContextClassLoader();
        try {
            thread.setContextClassLoader(pluginLoader);
            try {
                MemShellRegistry.getInstance().init();
            } catch (RuntimeException | LinkageError e) {
                warnings.add("初始化 server/shellTool 插件失败: " + SpiLoader.message(e));
            }
            try {
                PackerRegistry.getInstance().init();
            } catch (RuntimeException | LinkageError e) {
                warnings.add("初始化 packer 插件失败: " + SpiLoader.message(e));
            }
        } finally {
            // 预热的 provider 会保留自己的 defining loader；恢复 TCCL 可避免加载 GuiExtension、
            // Spring 自动配置及插件中的其他 SPI。
            thread.setContextClassLoader(originalLoader);
        }
        warnings.addAll(MemShellRegistry.getInstance().getLoadErrors());
        warnings.addAll(PackerRegistry.getInstance().getLoadErrors());
        return new PluginLoadResult(normalizedDirectory, loadedJars, warnings);
    }

    static Path resolvePluginDirectory(String configured, Path baseDirectory) {
        Path normalizedBase = baseDirectory.toAbsolutePath().normalize();
        if (isBlank(configured)) {
            return normalizedBase.resolve("plugins");
        }
        Path configuredPath = Paths.get(configured.trim());
        return configuredPath.isAbsolute() ? configuredPath.normalize()
                : normalizedBase.resolve(configuredPath).normalize();
    }

    static Path launchBaseDirectory(String classPath, String javaCommand, String userDir) {
        Path fallback = Paths.get(isBlank(userDir) ? "." : userDir).toAbsolutePath().normalize();
        if (isBlank(classPath) || classPath.indexOf(File.pathSeparatorChar) >= 0
                || !commandReferencesClassPath(javaCommand, classPath)) {
            return fallback;
        }
        try {
            Path candidate = Paths.get(classPath).toAbsolutePath().normalize();
            String fileName = candidate.getFileName() == null ? "" : candidate.getFileName().toString();
            if (fileName.toLowerCase(Locale.ROOT).endsWith(".jar") && Files.isRegularFile(candidate)) {
                Path parent = candidate.getParent();
                return parent == null ? fallback : parent;
            }
        } catch (RuntimeException ignored) {
            // 非标准启动场景回退到工作目录，不阻止宿主启动。
        }
        return fallback;
    }

    static List<Path> scanPluginJars(Path directory, List<String> warnings) {
        List<Path> jars = new ArrayList<>();
        try {
            if (!Files.exists(directory)) {
                return Collections.emptyList();
            }
            if (!Files.isDirectory(directory)) {
                warnings.add("插件目录不是目录: " + directory);
                return Collections.emptyList();
            }
            try (DirectoryStream<Path> entries = Files.newDirectoryStream(directory)) {
                for (Path entry : entries) {
                    String fileName = entry.getFileName().toString();
                    if (fileName.toLowerCase(Locale.ROOT).endsWith(".jar") && Files.isRegularFile(entry)) {
                        jars.add(entry.toAbsolutePath().normalize());
                    }
                }
            }
        } catch (IOException | RuntimeException e) {
            warnings.add("扫描插件目录失败: " + directory + ": " + SpiLoader.message(e));
            return Collections.emptyList();
        }
        jars.sort(Comparator.comparing(path -> path.getFileName().toString()));
        return jars;
    }

    private static boolean hasValidServiceDescriptors(Path jar, List<String> warnings) {
        try (JarFile jarFile = new JarFile(jar.toFile())) {
            for (String service : SPI_SERVICES) {
                JarEntry entry = jarFile.getJarEntry("META-INF/services/" + service);
                if (entry == null) {
                    continue;
                }
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                        jarFile.getInputStream(entry), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        int comment = line.indexOf('#');
                        String className = (comment >= 0 ? line.substring(0, comment) : line).trim();
                        if (!className.isEmpty() && !isJavaClassName(className)) {
                            throw new IOException("无效 SPI 实现类名: " + className);
                        }
                    }
                }
            }
            return true;
        } catch (IOException | RuntimeException e) {
            warnings.add("跳过损坏插件 jar: " + jar + ": " + SpiLoader.message(e));
            return false;
        }
    }

    private static boolean isJavaClassName(String className) {
        String[] segments = className.split("\\.", -1);
        for (String segment : segments) {
            if (segment.isEmpty() || !Character.isJavaIdentifierStart(segment.charAt(0))) {
                return false;
            }
            for (int i = 1; i < segment.length(); i++) {
                if (!Character.isJavaIdentifierPart(segment.charAt(i))) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean commandReferencesClassPath(String javaCommand, String classPath) {
        if (javaCommand == null) {
            return false;
        }
        String command = javaCommand.trim();
        return command.equals(classPath) || command.startsWith(classPath + " ")
                || command.startsWith(classPath + "\t") || command.equals('"' + classPath + '"')
                || command.startsWith('"' + classPath + "\" ") || command.startsWith('"' + classPath + "\"\t");
    }

    private static boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }
}
