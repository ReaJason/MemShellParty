package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.asm.ClassRenameUtils;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

/**
 * @author ReaJason
 * @since 2025/3/18
 */
public class CustomShellGenerator {

    private final ShellConfig shellConfig;
    private final CustomConfig customConfig;

    public CustomShellGenerator(ShellConfig shellConfig, CustomConfig customConfig) {
        this.shellConfig = shellConfig;
        this.customConfig = customConfig;
    }

    public byte[] getBytes() {
        String shellClassBase64 = customConfig.getShellClassBase64();

        if (StringUtils.isBlank(shellClassBase64)) {
            throw new IllegalArgumentException("Custom shell class is empty");
        }

        byte[] bytes = ClassRenameUtils.renameClass(Base64.decodeBase64(shellClassBase64), customConfig.getShellClassName());

        return ClassBytesShrink.shrink(bytes, shellConfig.isShrink());
    }
}
