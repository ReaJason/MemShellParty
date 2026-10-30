package com.reajason.javaweb.memshell;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * 一次启动期插件装载的结果。插件 jar 与诊断均不可变，供宿主记录日志或显示警告。
 */
public final class PluginLoadResult {
    private final Path directory;
    private final List<Path> pluginJars;
    private final List<String> warnings;

    PluginLoadResult(Path directory, List<Path> pluginJars, List<String> warnings) {
        this.directory = directory;
        this.pluginJars = Collections.unmodifiableList(new ArrayList<>(pluginJars));
        this.warnings = Collections.unmodifiableList(new ArrayList<>(warnings));
    }

    public Path getDirectory() {
        return directory;
    }

    public List<Path> getPluginJars() {
        return pluginJars;
    }

    public List<String> getWarnings() {
        return warnings;
    }

    public boolean hasWarnings() {
        return !warnings.isEmpty();
    }
}
