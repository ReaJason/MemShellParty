package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Base64;

/**
 * 文件保存/选择工具。
 */
public final class FileSaveUtil {

    private FileSaveUtil() {
    }

    /**
     * 保存文本内容为 .txt。
     */
    public static void saveText(Component parent, String suggestedName, String content) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter("文本文件 (*.txt)", "txt"));
        if (file == null) {
            return;
        }
        writeBytes(file, content.getBytes("UTF-8"));
    }

    /**
     * 将 base64 解码后按二进制保存（.class / .jar）。
     */
    public static void saveBase64AsBytes(Component parent, String suggestedName, String base64, String extension) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter(extension.toUpperCase() + " 文件 (*." + extension + ")", extension));
        if (file == null) {
            return;
        }
        writeBytes(file, decodeBase64(base64));
    }

    private static File chooseFile(Component parent, String suggestedName, FileNameExtensionFilter filter) {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("保存文件");
        chooser.setSelectedFile(new File(suggestedName));
        chooser.setFileFilter(filter);
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
        return file;
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
