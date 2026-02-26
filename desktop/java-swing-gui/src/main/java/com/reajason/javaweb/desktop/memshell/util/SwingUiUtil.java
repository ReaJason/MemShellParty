package com.reajason.javaweb.desktop.memshell.util;

import javax.swing.*;
import java.awt.*;

public final class SwingUiUtil {
    private SwingUiUtil() {}

    public static JPanel titledPanel(String title, LayoutManager layout) {
        JPanel panel = new JPanel(layout);
        panel.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createTitledBorder(title),
                BorderFactory.createEmptyBorder(6, 6, 6, 6)));
        return panel;
    }

    public static void showError(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "错误", JOptionPane.ERROR_MESSAGE);
    }

    public static void showInfo(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "提示", JOptionPane.INFORMATION_MESSAGE);
    }

    public static void runOnEdt(Runnable runnable) {
        if (SwingUtilities.isEventDispatchThread()) {
            runnable.run();
        } else {
            SwingUtilities.invokeLater(runnable);
        }
    }
}
