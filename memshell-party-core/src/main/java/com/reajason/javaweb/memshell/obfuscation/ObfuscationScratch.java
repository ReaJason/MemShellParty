package com.reajason.javaweb.memshell.obfuscation;

import java.nio.file.Path;

/**
 * 每次混淆调用的临时目录（thread-scoped）。
 * <p>
 * class-obf 的临时 class、产物输出和依赖目录都写成相对路径（{@code Const.TEMP_PATH}、
 * {@code FileUtil} 拼出的 {@code xxx_obf.class}），相对路径由进程 CWD 解析。容器里以非 root
 * 用户运行、或从只读目录启动 jar 时 CWD 不可写，混淆就会直接失败。
 * <p>
 * 这里把本次调用的临时目录放进 ThreadLocal，并让 {@link ClassObfRuntime} 在隔离类加载器中
 * 改写 class-obf 的 {@code Const} / {@code FileUtil} 从该 ThreadLocal 取值，所有中间文件
 * 都落到本次调用的 workDir，CWD 不再参与。
 * <p>
 * 改写后的 FileUtil 由隔离类加载器定义在 {@code me.n1ar4.clazz.obfuscator.utils} 包中，与本类
 * 不在同一个运行时包内，因此这里被它调用的方法必须是 public。
 *
 * @author ReaJason
 */
public final class ObfuscationScratch {

    private static final ThreadLocal<Path> WORK_DIR = new ThreadLocal<Path>();

    private ObfuscationScratch() {
    }

    static void enter(Path workDir) {
        WORK_DIR.set(workDir);
    }

    static void exit() {
        WORK_DIR.remove();
    }

    /**
     * class-obf {@code Const.TEMP_PATH} 的绝对路径；未被隔离类加载器接管时退回 class-obf 原行为。
     */
    public static String tempFileName() {
        Path workDir = WORK_DIR.get();
        return workDir == null ? "class-obf-temp.class" : workDir.resolve("class-obf-temp.class").toString();
    }

    /**
     * class-obf 产物文件名（不含扩展名）的绝对路径；未被隔离类加载器接管时退回原行为。
     */
    public static String outputStem(Path input) {
        String fileName = input.getFileName().toString();
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            fileName = fileName.substring(0, dotIndex);
        }
        Path workDir = WORK_DIR.get();
        return workDir == null ? fileName : workDir.resolve(fileName).toString();
    }
}
