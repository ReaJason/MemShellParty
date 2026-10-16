package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;

/**
 * @author ReaJason
 * @since 2025/12/7
 */
public class ShrinkPostProcessor implements Processor<byte[]> {

    @Override
    public byte[] process(byte[] bytes, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        return ClassBytesShrink.shrink(bytes, shellConfig.isShrink());
    }
}
