package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
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

    private static void writeBytes(File file, byte[] bytes) throws IOException {
        OutputStream os = new FileOutputStream(file);
        try {
            os.write(bytes);
        } finally {
            os.close();
        }
    }
}
