package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public interface Processor<T> {
    T process(T input, ShellConfig shellConfig, ShellToolConfig shellToolConfig);
}
