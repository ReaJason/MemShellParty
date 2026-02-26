package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class FileSaveUtil {
    private FileSaveUtil() {}

    public static void saveText(Component parent, String suggestedName, String content) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter("Text", "txt"));
        if (file == null) return;
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write((content == null ? "" : content).getBytes(StandardCharsets.UTF_8));
        }
    }

    public static void saveBase64AsBytes(Component parent, String suggestedName, String base64, String extension) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter(extension.toUpperCase(), extension));
        if (file == null) return;
        byte[] bytes = Base64.getDecoder().decode(base64 == null ? "" : base64);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(bytes);
        }
    }

    public static void saveBytes(Component parent, String suggestedName, byte[] bytes, String extension) throws IOException {
        File file = chooseFile(parent, suggestedName, new FileNameExtensionFilter(extension.toUpperCase(), extension));
        if (file == null) return;
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(bytes);
        }
    }

    public static File chooseFile(Component parent, String suggestedName, FileNameExtensionFilter filter) {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File(suggestedName));
        chooser.setFileFilter(filter);
        int result = chooser.showSaveDialog(parent);
        if (result != JFileChooser.APPROVE_OPTION) {
            return null;
        }
        return chooser.getSelectedFile();
    }
}
