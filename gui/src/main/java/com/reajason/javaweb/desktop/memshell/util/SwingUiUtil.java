package com.reajason.javaweb.desktop.memshell.util;

import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
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

    /**
     * labeled 行面板上的 client property：错误红字标签与对应输入组件。
     */
    private static final String ERROR_LABEL_KEY = "memshell.errorLabel";

    /**
     * FlatLaf 红描边 client property 键（= FlatClientProperties.OUTLINE，未安装 FlatLaf 时无害）。
     */
    private static final String OUTLINE_KEY = "JComponent.outline";

    private static final Color FALLBACK_SUCCESS = new Color(0x1F, 0x8A, 0x4C);
    private static final Color FALLBACK_ERROR = new Color(0xD1, 0x2B, 0x22);
    private static final Color FALLBACK_MUTED = new Color(0x86, 0x8B, 0x92);

    private SwingUiUtil() {
    }

    /**
     * 表单项：label 居左（固定列宽右对齐），field 居右填满，替代上下堆叠。
     * 行内附带隐藏的错误红字标签（hidemode 3 不占位），供 inline 校验使用。
     */
    public static JPanel labeled(String label, JComponent component) {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, gapx 8, gapy 1, wrap 2", "[" + LABEL_WIDTH + "!,right][grow,fill]", "[][]"));
        p.add(new JLabel(label));
        if (component instanceof JComboBox) {
            component.setPreferredSize(new Dimension(120, component.getPreferredSize().height));
        }
        p.add(component, "growx");
        JLabel errorLabel = createErrorLabel();
        p.add(errorLabel, "span 2, growx, hidemode 3");
        p.putClientProperty(ERROR_LABEL_KEY, errorLabel);
        return p;
    }

    /**
     * 错误红字标签：默认隐藏不占位；前景色随主题（updateUI 时重读调色板）。
     */
    public static JLabel createErrorLabel() {
        JLabel label = new JLabel() {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(errorColor());
            }
        };
        label.setVisible(false);
        return label;
    }

    /**
     * 把错误标签挂到载体组件上，使 {@link #setFieldError} / {@link #clearFieldErrors} 能沿父链找到它。
     * 供非 {@link #labeled} 布局（打包条、Custom 面板）复用同一套 inline 校验机制。
     */
    public static void attachErrorLabel(JComponent carrier, JLabel errorLabel) {
        carrier.putClientProperty(ERROR_LABEL_KEY, errorLabel);
    }

    /**
     * inline 校验：字段红描边（FlatLaf outline=error）+ 行内红字。
     */
    public static void setFieldError(JComponent field, String message) {
        setOutlineError(field, true);
        JLabel errorLabel = findErrorLabel(field);
        if (errorLabel != null) {
            errorLabel.setText(message);
            errorLabel.setVisible(true);
            Container parent = errorLabel.getParent();
            if (parent != null) {
                parent.revalidate();
                parent.repaint();
            }
        }
    }

    /**
     * 清掉单个字段的错误态（用户重新编辑该字段时调用）。
     */
    public static void clearFieldError(JComponent field) {
        setOutlineError(field, false);
        JLabel errorLabel = findErrorLabel(field);
        if (errorLabel != null) {
            errorLabel.setVisible(false);
        }
    }

    /**
     * 递归清掉整棵树上的错误描边与错误红字（结构性变更/重新生成时调用）。
     */
    public static void clearFieldErrors(Container root) {
        for (Component c : root.getComponents()) {
            if (c instanceof JComponent) {
                JComponent jc = (JComponent) c;
                if ("error".equals(jc.getClientProperty(OUTLINE_KEY))) {
                    jc.putClientProperty(OUTLINE_KEY, null);
                }
                Object label = jc.getClientProperty(ERROR_LABEL_KEY);
                if (label instanceof JLabel) {
                    ((JLabel) label).setVisible(false);
                }
            }
            if (c instanceof Container) {
                clearFieldErrors((Container) c);
            }
        }
    }

    private static void setOutlineError(JComponent field, boolean error) {
        Object value = error ? "error" : null;
        field.putClientProperty(OUTLINE_KEY, value);
        // JTextArea 等多行组件在 JScrollPane 里时边框画在 scrollpane 上，两处都标记以兼容不同 LAF
        if (field.getParent() instanceof JViewport && field.getParent().getParent() instanceof JScrollPane) {
            ((JComponent) field.getParent().getParent()).putClientProperty(OUTLINE_KEY, value);
        }
    }

    private static JLabel findErrorLabel(JComponent field) {
        for (Container c = field.getParent(); c != null; c = c.getParent()) {
            if (c instanceof JComponent) {
                Object label = ((JComponent) c).getClientProperty(ERROR_LABEL_KEY);
                if (label instanceof JLabel) {
                    return (JLabel) label;
                }
            }
        }
        return null;
    }

    public static void showError(Component parent, String message) {
        JOptionPane.showMessageDialog(parent, message, "错误", JOptionPane.ERROR_MESSAGE);
    }

    /**
     * 语义色全部走 UIManager/FlatLaf 调色板键，暗色主题切换后自动正确；
     * 键缺失（非 FlatLaf 主题，如未安装主题的测试环境）时回退原色值。
     */
    public static Color successColor() {
        return paletteColor("Actions.Green", FALLBACK_SUCCESS);
    }

    public static Color errorColor() {
        return paletteColor("Actions.Red", FALLBACK_ERROR);
    }

    public static Color mutedColor() {
        return paletteColor("Label.disabledForeground", FALLBACK_MUTED);
    }

    private static Color paletteColor(String key, Color fallback) {
        Color color = UIManager.getColor(key);
        return color != null ? color : fallback;
    }

    /**
     * 复制并给按钮短暂「已复制」反馈，替代无感的静默复制。
     */
    public static void copyWithFeedback(final JButton source, String text) {
        final String originalText = source.getText();
        final String originalTooltip = source.getToolTipText();
        final boolean copied = ClipboardUtil.copyText(text);
        // 不追加 ✓ 等默认字体不含的符号：macOS 26 + JDK<26 混合脚本渲染会污染字形缓存（整窗缺字），规则详见 ResultPanel 空态提示注释
        source.setText(copied ? "已复制" : "复制失败");
        source.setToolTipText(copied ? originalTooltip : "系统剪贴板暂不可用，请重试");
        source.setEnabled(false);
        ActionListener restore = new ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                source.setText(originalText);
                source.setToolTipText(originalTooltip);
                source.setEnabled(true);
            }
        };
        Timer timer = new Timer(1200, restore);
        timer.setRepeats(false);
        timer.start();
    }

    /**
     * 复制摘要值并给标签反馈；失败时保留可重试的明确提示，而不是伪装成成功。
     */
    public static void copyLabelWithFeedback(final JLabel label, String text) {
        final String originalTooltip = label.getToolTipText();
        boolean copied = ClipboardUtil.copyText(text);
        label.setToolTipText(copied ? originalTooltip : "复制失败：系统剪贴板暂不可用，请重试");
        flashLabel(label, copied ? successColor() : errorColor());
        if (!copied) {
            Timer timer = new Timer(1600, new ActionListener() {
                @Override
                public void actionPerformed(java.awt.event.ActionEvent e) {
                    label.setToolTipText(originalTooltip);
                }
            });
            timer.setRepeats(false);
            timer.start();
        }
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
