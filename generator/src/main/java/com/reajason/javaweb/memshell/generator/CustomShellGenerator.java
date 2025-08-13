package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import org.apache.commons.lang3.StringUtils;

import java.util.Base64;

/**
 * @author ReaJason
 * @since 2025/3/18
 */
public class CustomShellGenerator extends ASMShellGenerator<CustomConfig> {

    public CustomShellGenerator(ShellConfig shellConfig, CustomConfig customConfig) {
        super(shellConfig, customConfig);
    }

    @Override
    public byte[] getBytes() {
        String shellClassBase64 = shellToolConfig.getShellClassBase64();

        if (StringUtils.isBlank(shellClassBase64)) {
            throw new GenerationException("Custom shell class is empty");
        }
        byte[] classBytes = Base64.getDecoder().decode(shellClassBase64);
        byte[] bytes = ClassRenameUtils.renameClass(classBytes, shellToolConfig.getShellClassName());
        return ClassBytesShrink.shrink(bytes, shellConfig.isShrink());
    }
}
