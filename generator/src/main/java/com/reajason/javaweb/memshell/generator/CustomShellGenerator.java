package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.ClassBytesShrink;
import com.reajason.javaweb.memshell.config.CustomConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.jar.asm.ClassReader;
import net.bytebuddy.jar.asm.ClassWriter;
import net.bytebuddy.jar.asm.commons.ClassRemapper;
import net.bytebuddy.jar.asm.commons.SimpleRemapper;
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

        byte[] bytes = renameClass(Base64.decodeBase64(shellClassBase64), customConfig.getShellClassName());

        return ClassBytesShrink.shrink(bytes, shellConfig.isShrink());
    }

    private static byte[] renameClass(byte[] classBytes, String newName) {
        ClassReader reader = null;
        try {
            reader = new ClassReader(classBytes);
        } catch (Exception e) {
            throw new RuntimeException("invalid class bytes");
        }
        String oldClassName = reader.getClassName();
        String newClassName = newName.replace('.', '/');
        ClassWriter writer = new ClassWriter(reader, ClassWriter.COMPUTE_MAXS | ClassWriter.COMPUTE_FRAMES);
        ClassRemapper adapter = new ClassRemapper(writer, new SimpleRemapper(oldClassName, newClassName));
        reader.accept(adapter, 0);
        return writer.toByteArray();
    }
}
