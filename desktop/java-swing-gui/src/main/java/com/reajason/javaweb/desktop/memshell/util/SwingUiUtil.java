package com.reajason.javaweb.desktop.memshell.util;

import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.Timer;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.event.ActionListener;

/**
 * Swing 弹窗与轻量反馈工具。
 */
public final class SwingUiUtil {

    /**
     * 表单标签列宽：右对齐，容纳最长标签（如「内存马挂载类型」）并留字体余量。
     */
    private static final int LABEL_WIDTH = 100;

    private static final Color SUCCESS_COLOR = new Color(0x1F, 0x8A, 0x4C);
    private static final Color ERROR_COLOR = new Color(0xD1, 0x2B, 0x22);
    private static final Color MUTED_COLOR = new Color(0x86, 0x8B, 0x92);

    private SwingUiUtil() {
    }

    /**
     * 表单项：label 居左（固定列宽右对齐），field 居右填满，替代上下堆叠。
     */
    public static JPanel labeled(String label, JComponent component) {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[" + LABEL_WIDTH + "!,right][grow,fill]", "[]"));
        p.add(new JLabel(label));
        if (component instanceof JComboBox) {
            component.setPreferredSize(new Dimension(120, component.getPreferredSize().height));
        }
        p.add(component, "growx");
        return p;
    }

    public static void showError(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "错误", JOptionPane.ERROR_MESSAGE);
    }

    public static Color successColor() {
        return SUCCESS_COLOR;
    }

    public static Color errorColor() {
        return ERROR_COLOR;
    }

    public static Color mutedColor() {
        return MUTED_COLOR;
    }

    /**
     * 复制并给按钮短暂「已复制」反馈，替代无感的静默复制。
     */
    public static void copyWithFeedback(final JButton source, String text) {
        ClipboardUtil.copyText(text);
        final String originalText = source.getText();
        source.setText("已复制 ✓");
        source.setEnabled(false);
        ActionListener restore = new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                source.setText(originalText);
                source.setEnabled(true);
            }
        };
        Timer timer = new Timer(1200, restore);
        timer.setRepeats(false);
        timer.start();
    }

    private static final String FLASH_ORIGINAL_FG = "swinguiutil.flashOriginalFg";

    /**
     * 标签前景色短暂高亮（值点击复制反馈），可安全重入。
     */
    public static void flashLabel(final JLabel label, Color highlight) {
        Object saved = label.getClientProperty(FLASH_ORIGINAL_FG);
        if (saved == null) {
            label.putClientProperty(FLASH_ORIGINAL_FG, label.getForeground());
        }
        label.setForeground(highlight);
        Timer timer = new Timer(800, new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                Object original = label.getClientProperty(FLASH_ORIGINAL_FG);
                if (original instanceof Color) {
                    label.setForeground((Color) original);
                }
                label.putClientProperty(FLASH_ORIGINAL_FG, null);
            }
        });
        timer.setRepeats(false);
        timer.start();
    }
}
