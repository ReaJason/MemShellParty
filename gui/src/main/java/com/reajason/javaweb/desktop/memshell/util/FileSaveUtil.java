package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Base64;

/**
 * 文件保存/选择工具。
 * 会话内记忆上次目录（跨重启持久化留给 ~/.memshellparty 配置一并解决）；
 * 覆盖已存在文件前弹确认，拒绝则回到选择框。
 */
public final class FileSaveUtil {

    private static File lastDirectory;

    private FileSaveUtil() {
    }

    /**
     * 保存文本内容为 .txt。
     *
     * @return 实际保存的文件；用户取消或拒绝覆盖时返回 null
     */
    public static File saveText(Component parent, String suggestedName, String content) throws IOException {
        return saveText(parent, suggestedName, content, "txt");
    }

    /**
     * 保存文本内容，扩展名可指定（如反编译源码用 java）。
     *
     * @return 实际保存的文件；用户取消或拒绝覆盖时返回 null
     */
    public static File saveText(Component parent, String suggestedName, String content, String extension) throws IOException {
        String filterDescription = "java".equals(extension) ? "Java 源文件 (*.java)" : "文本文件 (*." + extension + ")";
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter(filterDescription, extension));
        if (file == null) {
            return null;
        }
        writeBytes(file, content.getBytes("UTF-8"));
        return file;
    }

    /**
     * 将 base64 解码后按二进制保存（.class / .jar）。
     *
     * @return 实际保存的文件；用户取消或拒绝覆盖时返回 null
     */
    public static File saveBase64AsBytes(Component parent, String suggestedName, String base64, String extension) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter(extension.toUpperCase() + " 文件 (*." + extension + ")", extension));
        if (file == null) {
            return null;
        }
        writeBytes(file, decodeBase64(base64));
        return file;
    }

    /**
     * 打开文件选择框的初始目录（供 Custom 面板的 .class 选择器共享目录记忆）。
     */
    public static File getLastDirectory() {
        return lastDirectory;
    }

    /**
     * 由全限定类名生成简单文件名（如 com.example.Foo + ".java" → Foo.java）。
     */
    public static String simpleFileName(String className, String extension) {
        if (className == null || className.trim().isEmpty()) return "output" + extension;
        int idx = className.lastIndexOf('.');
        return (idx >= 0 ? className.substring(idx + 1) : className) + extension;
    }

    /**
     * 选中文件后记下其所在目录。
     */
    public static void rememberDirectory(File file) {
        if (file == null) {
            return;
        }
        File dir = file.isDirectory() ? file : file.getParentFile();
        if (dir != null) {
            lastDirectory = dir;
        }
    }

    private static File chooseFile(Component parent, String suggestedName, FileNameExtensionFilter filter) {
        JFileChooser chooser = new JFileChooser(lastDirectory);
        chooser.setDialogTitle("保存文件");
        chooser.setSelectedFile(new File(suggestedName));
        chooser.setFileFilter(filter);
        while (true) {
            int result = chooser.showSaveDialog(parent);
            if (result != JFileChooser.APPROVE_OPTION) {
                return null;
            }
            File file = chooser.getSelectedFile();
            // 未带扩展名时按过滤器补齐
            String ext = filter.getExtensions().length > 0 ? filter.getExtensions()[0] : null;
            if (ext != null && !file.getName().toLowerCase().endsWith("." + ext.toLowerCase())) {
                file = new File(file.getParentFile(), file.getName() + "." + ext);
            }
            // Swing JFileChooser 不做覆盖确认，需手动拦截
            if (file.exists() && !confirmOverwrite(parent, file)) {
                continue;
            }
            lastDirectory = file.getParentFile();
            return file;
        }
    }

    private static boolean confirmOverwrite(Component parent, File file) {
        int choice = JOptionPane.showConfirmDialog(parent,
                "文件已存在：\n" + file.getAbsolutePath() + "\n是否覆盖？",
                "确认覆盖",
                JOptionPane.YES_NO_OPTION,
                JOptionPane.WARNING_MESSAGE);
        return choice == JOptionPane.YES_OPTION;
    }

    private static byte[] decodeBase64(String base64) {
        if (base64 == null || base64.trim().isEmpty()) {
            return new byte[0];
        }
        return Base64.getDecoder().decode(base64.trim());
    }

    /**
     * 写入同目录临时文件后再替换目标，避免目标文件在写入失败时被截断。
     * 同目录创建临时文件也保证了替换不会跨文件系统。
     */
    private static void writeBytes(File file, byte[] bytes) throws IOException {
        Path target = file.toPath();
        Path parent = target.toAbsolutePath().getParent();
        Path temporary = Files.createTempFile(parent, "." + file.getName() + ".", ".tmp");
        boolean installed = false;
        try {
            FileOutputStream output = new FileOutputStream(temporary.toFile());
            try {
                output.write(bytes);
                output.flush();
            } finally {
                output.close();
            }

            try {
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException | FileAlreadyExistsException ex) {
                replaceWithoutAtomicMove(temporary, target);
            }
            installed = true;
        } finally {
            if (!installed) {
                Files.deleteIfExists(temporary);
            }
        }
    }

    /**
     * 原子替换不可用时先把旧文件移到同目录备份；新文件安装失败则回滚旧文件。
     * 这比直接以写入流打开目标更安全，尤其适用于网络盘或较老的文件系统。
     */
    private static void replaceWithoutAtomicMove(Path temporary, Path target) throws IOException {
        Path backup = null;
        if (Files.exists(target, LinkOption.NOFOLLOW_LINKS)) {
            backup = Files.createTempFile(target.toAbsolutePath().getParent(), "." + target.getFileName() + ".", ".backup");
            Files.deleteIfExists(backup);
            try {
                Files.move(target, backup);
            } catch (IOException ex) {
                Files.deleteIfExists(backup);
                throw ex;
            }
        }
        try {
            Files.move(temporary, target);
        } catch (IOException ex) {
            if (backup != null) {
                try {
                    Files.move(backup, target, StandardCopyOption.REPLACE_EXISTING);
                } catch (IOException rollbackFailure) {
                    ex.addSuppressed(rollbackFailure);
                }
            }
            throw ex;
        }
        if (backup != null) {
            // 新文件已经安装成功；无法删除备份不应把一次成功保存报告成失败。
            try {
                Files.deleteIfExists(backup);
            } catch (IOException ignored) {
                // Best effort cleanup; the backup is in the same directory and harmless.
            }
        }
    }
}
