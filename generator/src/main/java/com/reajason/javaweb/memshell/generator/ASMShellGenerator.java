package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

/**
 * @author ReaJason
 * @since 2025/5/27
 */
public abstract class ASMShellGenerator<T extends ShellToolConfig> implements ShellGenerator {
    protected final ShellConfig shellConfig;
    protected final T shellToolConfig;

    protected ASMShellGenerator(ShellConfig shellConfig, T shellToolConfig) {
        this.shellConfig = shellConfig;
        this.shellToolConfig = shellToolConfig;
    }
}
