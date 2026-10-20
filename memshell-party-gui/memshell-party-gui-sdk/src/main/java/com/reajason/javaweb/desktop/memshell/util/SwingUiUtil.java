package com.reajason.javaweb.desktop.memshell.util;

import net.miginfocom.swing.MigLayout;

import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JViewport;
import javax.swing.SwingUtilities;
import javax.swing.Timer;
import javax.swing.UIManager;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
import java.awt.Dimension;
import java.awt.GraphicsConfiguration;
import java.awt.GraphicsEnvironment;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.Window;
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
     * 与 {@link #labeled} 行输入框左边缘对齐所需的左缩进（标签列宽 + 标签/输入框间距），
     * 供不套用 labeled 但需要和表单字段对齐的整行控件（如开关行、混淆参数）使用。
     */
    public static final int FIELD_COLUMN_INSET = LABEL_WIDTH + 8;

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
     * 桌面窗口统一尺寸策略：整体收窄伸长（配置项改为左右布局后不再需要宽屏），
     * 小屏按可用区域收缩，宽高都不超过屏幕可用范围，并设最小尺寸防挤压。
     * 两个生成器 frame 与官方发行版外壳窗口共用，宿主自建窗口也可以直接调。
     */
    public static void sizeToScreen(JFrame frame) {
        sizeToScreen(frame, 1020, 980);
    }

    /**
     * 带宽度上限的尺寸策略：内容更宽的宿主窗口（如综合利用工具的双栏布局）把上限放大，
     * 其余规则（小屏收缩、不超屏幕、最小尺寸）一致。
     */
    public static void sizeToScreen(JFrame frame, int maxWidth, int maxHeight) {
        GraphicsConfiguration config = frame.getGraphicsConfiguration();
        Insets screenInsets = Toolkit.getDefaultToolkit().getScreenInsets(config);
        Dimension screen = config == null ? Toolkit.getDefaultToolkit().getScreenSize() : config.getBounds().getSize();
        int availWidth = screen.width - screenInsets.left - screenInsets.right;
        int availHeight = screen.height - screenInsets.top - screenInsets.bottom;

        int width = Math.min(Math.min(Math.max(availWidth - 80, 940), maxWidth), availWidth);
        int height = Math.min(Math.min(Math.max(availHeight - 60, 820), maxHeight), availHeight);
        frame.setMinimumSize(new Dimension(Math.min(940, availWidth), Math.min(760, availHeight)));
        frame.setSize(width, height);
    }

    /**
     * 把承载 {@code component} 的窗口收进它所在屏幕的边界内：只缩不放，只把出界的边挪回来。
     *
     * <p>宿主窗口常按固定像素设计（如 Godzilla 的会话窗口按 1920 设计稿缩放），小屏上会超出
     * 屏幕，右侧的注入/复制/保存按钮直接被挡在屏幕外。嵌入方在界面首次显示时调一次即可。
     *
     * @return 是否调整过窗口位置或大小
     */
    public static boolean fitWindowToScreen(Component component) {
        if (component == null || GraphicsEnvironment.isHeadless()) {
            return false;
        }
        Window window = SwingUtilities.getWindowAncestor(component);
        if (window == null || !window.isShowing()) {
            return false;
        }
        GraphicsConfiguration config = window.getGraphicsConfiguration();
        if (config == null) {
            return false;
        }
        Rectangle screen = config.getBounds();
        int width = Math.min(window.getWidth(), screen.width);
        int height = Math.min(window.getHeight(), screen.height);
        int x = Math.min(Math.max(window.getX(), screen.x), screen.x + screen.width - width);
        int y = Math.min(Math.max(window.getY(), screen.y), screen.y + screen.height - height);
        if (width == window.getWidth() && height == window.getHeight()
                && x == window.getX() && y == window.getY()) {
            return false;
        }
        window.setSize(width, height);
        window.setLocation(x, y);
        window.validate();
        return true;
    }

    /**
     * 浮层提示（toast）：在 owner 所在窗口底部弹一个圆角浮层，淡入 → 停留 → 淡出后自动移除。
     * 不抢焦点、不参与布局（不改任何组件尺寸）、不挡鼠标——用于「用户操作当场被拒」这类
     * 需要立刻看见、但不值得弹窗也不该在表单里铺错误 label 的提示（同一窗口后一条顶掉前一条）。
     *
     * <p>提示文案通常还应同时写进日志区留档：浮层看完就没了，日志才是可回看的记录。
     */
    public static void showToast(Component owner, String message) {
        Toast.show(owner, message);
    }

    /**
     * 动作按钮：执行动作而不承载参数的按钮用这个建（已有按钮调 {@link #markActionButton}）。
     *
     * <p>为什么要专门一个工厂——这些按钮会进出忙碌态（{@code setEnabled(false)} 禁用自己、跑完再放开），
     * 而 Swing 在「当前焦点持有者被禁用」时会把焦点交给焦点遍历序里的**下一个组件**：生成器里
     * 「生成内存马」后面正是配置输入框，FlatLaf 默认 {@code TextComponent.selectAllOnFocusPolicy=once}
     * 再把它整段选中，看着像被误选，而且下一次输入会直接顶掉原文。按钮不参与焦点遍历后，点击动作
     * 不再把焦点从用户刚编辑的字段里带走，禁用时也没有焦点可移交；鼠标点击、Ctrl/⌘ + Enter、
     * 默认按钮、快捷键这些路径都不受影响（只是它不再进 Tab 序）。
     */
    public static JButton actionButton(String text) {
        JButton button = new JButton(text);
        markActionButton(button);
        return button;
    }

    /**
     * 把一个已有按钮标成动作按钮（不参与焦点遍历）；{@link #copyWithFeedback} 会对传进来的按钮自动调用，
     * 宿主自己造的复制/执行按钮也建议显式调用。
     */
    public static void markActionButton(JButton button) {
        button.setFocusable(false);
    }

    /**
     * 复制并给按钮短暂「已复制」反馈，替代无感的静默复制。
     */
    public static void copyWithFeedback(final JButton source, String text) {
        final String originalText = source.getText();
        final String originalTooltip = source.getToolTipText();
        final boolean copied = ClipboardUtil.copyText(text);
        // 这个按钮马上要被禁用 1.2 秒：先让它退出焦点遍历，否则焦点会甩给下一个组件（原因见 actionButton）
        markActionButton(source);
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
