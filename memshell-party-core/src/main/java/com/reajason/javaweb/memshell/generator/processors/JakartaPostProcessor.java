package com.reajason.javaweb.memshell.generator.processors;

import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.Processor;

public class JakartaPostProcessor implements Processor<byte[]> {
    @Override
    public byte[] process(byte[] input, ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        if (shellConfig.isJakarta()) {
            return ClassRenameUtils.relocateJakarta(input);
        }
        return input;
    }
}
