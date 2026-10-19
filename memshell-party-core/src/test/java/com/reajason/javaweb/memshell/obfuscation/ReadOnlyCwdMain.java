package com.reajason.javaweb.memshell.obfuscation;

import com.reajason.javaweb.memshell.obfuscation.fixtures.OuterClass;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 子进程入口：在只读 CWD 中执行一次混淆，产出写到参数指定的可写位置。
 * 由 {@link ClassObfuscationTest#shouldObfuscateWhenWorkingDirectoryIsNotWritable()} 启动，
 * 用于验证混淆不再依赖进程 CWD 可写。
 */
public final class ReadOnlyCwdMain {

    private ReadOnlyCwdMain() {
    }

    public static void main(String[] args) throws Exception {
        Path cwd = Paths.get(".");
        if (Files.isWritable(cwd)) {
            throw new IllegalStateException("working directory is writable: " + cwd.toAbsolutePath());
        }
        String resource = OuterClass.class.getName().replace('.', '/') + ".class";
        byte[] input;
        try (InputStream in = ReadOnlyCwdMain.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalStateException("fixture class not found: " + resource);
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            input = out.toByteArray();
        }
        byte[] output = ClassObfuscation.obfuscate(input);
        Files.write(Paths.get(args[0]), output);
    }
}
