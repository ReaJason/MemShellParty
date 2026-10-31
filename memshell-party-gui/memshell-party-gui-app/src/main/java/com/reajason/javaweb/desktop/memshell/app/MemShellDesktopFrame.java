package com.reajason.javaweb.desktop.memshell.app;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatAnimatedLafChange;
import com.formdev.flatlaf.extras.FlatSVGIcon;
import com.reajason.javaweb.desktop.memshell.MemShellGui;
import com.reajason.javaweb.desktop.memshell.extension.GuiExtension;
import com.reajason.javaweb.desktop.memshell.ui.DecompileFrame;
import com.reajason.javaweb.desktop.memshell.ui.MemShellGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.ui.ProbeGeneratorFrame;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.SafetyDisclaimer;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRootPane;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.util.Collections;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * 官方完整发行版的外壳窗口：顶部「内存马 / 探测马 / 反编译」三页 Tab 共用底部状态栏。
 * 三个页面本体来自 SDK 的 {@link MemShellGeneratorFrame} / {@link ProbeGeneratorFrame} /
 * {@link DecompileFrame} —— 外壳（页签布局、状态栏、暗色切换、
 * 关于弹窗）在这里，下游想换成自己的布局时照抄这个类即可。
 *
 * <p>状态栏：左右两侧分别显示当前页的状态文案（每页各记一份，切页不串）与
 * 暗色切换 / 作者 / 关于入口；窗口标题取扩展解析后的应用标题。
 */
public class MemShellDesktopFrame extends JFrame {

    private static final String AUTHOR = "By ReaJason";

    private enum Page {
        MEM_SHELL,
        PROBE,
        DECOMPILE
    }

    private static final class PageStatus {
        private String message;
        private StatusReporter.Level level;

        private PageStatus(String message, StatusReporter.Level level) {
            this.message = message;
            this.level = level;
        }
    }

    private final MemShellGeneratorFrame memShellFrame;
    private final ProbeGeneratorFrame probeFrame;
    private final DecompileFrame decompileFrame;
    private final JTabbedPane pageTabs = new JTabbedPane();
    private final JLabel statusLabel = new JLabel("就绪");
    /** 每页一份状态文案：切页只换显示，不丢别的页报过的消息。 */
    private final Map<Page, PageStatus> pageStatuses = new EnumMap<Page, PageStatus>(Page.class);
    /** 页签内容 → 页枚举：切页判断按组件走，页签顺序改了也不会串。 */
    private final Map<Component, Page> pageByContent = new LinkedHashMap<Component, Page>();
    private AboutDialog aboutDialog;

    public MemShellDesktopFrame(List<GuiExtension> extensions) {
        super(MemShellGui.applicationTitle(extensions, "MemShellParty v" + AppVersion.get()));
        // standalone = false：三个页面只出界面，窗口属性归这个外壳
        this.memShellFrame = new MemShellGeneratorFrame(extensions, false);
        this.probeFrame = new ProbeGeneratorFrame(false);
        this.decompileFrame = new DecompileFrame(false);
        memShellFrame.setStatusReporter((message, level) -> updatePageStatus(Page.MEM_SHELL, message, level));
        probeFrame.setStatusReporter((message, level) -> updatePageStatus(Page.PROBE, message, level));
        decompileFrame.setStatusReporter((message, level) -> updatePageStatus(Page.DECOMPILE, message, level));
        for (Page page : Page.values()) {
            pageStatuses.put(page, new PageStatus("就绪", StatusReporter.Level.INFO));
        }

        addPage(Page.MEM_SHELL, "内存马", memShellFrame.getRootPanel());
        addPage(Page.PROBE, "探测马", probeFrame.getRootPanel());
        addPage(Page.DECOMPILE, "反编译", decompileFrame.getRootPanel());
        pageTabs.addChangeListener(e -> onPageChanged());

        setLayout(new BorderLayout());
        // 安全使用声明常驻顶部：不随页签切换消失，红字加粗（文案与 Shiro 利用工具共用）
        add(SafetyDisclaimer.createBanner(), BorderLayout.NORTH);
        add(pageTabs, BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        SwingUiUtil.sizeToScreen(this);
        setLocationRelativeTo(null);
        // 初始页的默认按钮与快捷键：切页时转移到新页
        installActivePageShortcut();
        renderActiveStatus();
    }

    /**
     * 安装 FlatLaf 并显示窗口：完整发行版的入口。
     */
    public static void launch() {
        launch(Collections.emptyList());
    }

    /**
     * @param pluginWarnings 已在启动日志中保留完整详情的插件诊断
     */
    public static void launch(final List<String> pluginWarnings) {
        // macOS 未打包 JVM 参数时让 Dock/菜单栏显示应用名
        if (System.getProperty("apple.awt.application.name") == null) {
            System.setProperty("apple.awt.application.name", "MemShellParty");
        }
        MemShellGui.setupLookAndFeel();
        final List<GuiExtension> extensions = MemShellGui.resolveExtensions();
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                MemShellDesktopFrame frame = new MemShellDesktopFrame(extensions);
                frame.setVisible(true);
                if (!pluginWarnings.isEmpty()) {
                    JOptionPane.showMessageDialog(frame,
                            "部分插件未能加载，详细信息请查看启动日志。",
                            "插件加载警告", JOptionPane.WARNING_MESSAGE);
                }
            }
        });
    }

    /**
     * 切页：默认按钮（裸 Enter）与 Ctrl/⌘ + Enter 交给新页，状态栏换成新页自己那份文案。
     */
    private void onPageChanged() {
        installActivePageShortcut();
        renderActiveStatus();
    }

    private void addPage(Page page, String title, JComponent content) {
        pageTabs.addTab(title, content);
        pageByContent.put(content, page);
    }

    private Page activePage() {
        Page page = pageByContent.get(pageTabs.getSelectedComponent());
        return page == null ? Page.MEM_SHELL : page;
    }

    /**
     * 先把三页的快捷键与默认按钮全摘掉，再给当前页装上：三页共用同一个击键，
     * 不卸旧的，别的页里敲 Ctrl(⌘) + Enter 会误触发上一个页面的主操作。
     */
    private void installActivePageShortcut() {
        JRootPane rootPane = getRootPane();
        memShellFrame.uninstallGenerateShortcut(rootPane);
        probeFrame.uninstallGenerateShortcut(rootPane);
        decompileFrame.uninstallDecompileShortcut(rootPane);
        switch (activePage()) {
            case PROBE:
                probeFrame.installGenerateShortcut(rootPane);
                break;
            case DECOMPILE:
                decompileFrame.installDecompileShortcut(rootPane);
                break;
            default:
                memShellFrame.installGenerateShortcut(rootPane);
                break;
        }
    }

    private void updatePageStatus(Page page, String message, StatusReporter.Level level) {
        PageStatus pageStatus = pageStatuses.get(page);
        pageStatus.message = message;
        pageStatus.level = level;
        if (page == activePage()) {
            renderActiveStatus();
        }
    }

    private void renderActiveStatus() {
        PageStatus pageStatus = pageStatuses.get(activePage());
        statusLabel.setForeground(statusColor(pageStatus.level));
        statusLabel.setText(pageStatus.message);
    }

    private Color statusColor(StatusReporter.Level level) {
        if (level == StatusReporter.Level.ERROR) {
            return SwingUiUtil.errorColor();
        }
        if (level == StatusReporter.Level.SUCCESS) {
            return SwingUiUtil.successColor();
        }
        return SwingUiUtil.mutedColor();
    }

    /**
     * 关于弹窗懒加载复用：重复打开仅重新居中并显示（弹窗自身 HIDE_ON_CLOSE）。
     */
    private void showAboutDialog() {
        if (aboutDialog == null) {
            aboutDialog = new AboutDialog(this);
        }
        aboutDialog.setLocationRelativeTo(this);
        aboutDialog.setVisible(true);
    }

    private JPanel buildStatusBar() {
        statusLabel.setForeground(SwingUiUtil.mutedColor());
        // 分隔线颜色随主题（updateUI 重读调色板），暗色切换不留亮色残影
        JPanel p = new JPanel(new BorderLayout()) {
            @Override
            public void updateUI() {
                super.updateUI();
                Color sep = UIManager.getColor("Separator.foreground");
                if (sep == null) {
                    sep = new Color(200, 200, 200);
                }
                setBorder(BorderFactory.createCompoundBorder(
                        BorderFactory.createMatteBorder(1, 0, 0, 0, sep),
                        BorderFactory.createEmptyBorder(3, 8, 3, 8)));
            }
        };
        p.add(statusLabel, BorderLayout.WEST);

        // 右侧：暗色切换 + 作者 + 关于按钮（SVG 图标）
        JPanel right = new JPanel(new MigLayout("insets 0, gapx 8", "[][][]", "[]"));
        final JCheckBox darkToggle = new JCheckBox("暗色") {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(SwingUiUtil.mutedColor());
            }
        };
        darkToggle.setSelected(FlatLaf.isLafDark());
        darkToggle.setToolTipText("切换 FlatLaf 亮色/暗色主题");
        darkToggle.addActionListener(e -> toggleTheme(darkToggle.isSelected()));
        right.add(darkToggle);
        right.add(new JLabel(AUTHOR) {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(SwingUiUtil.mutedColor());
            }
        });
        right.add(buildAboutButton());
        p.add(right, BorderLayout.EAST);
        return p;
    }

    /**
     * 构建「关于」图标按钮：updateUI 时重新创建 ColorFilter 将 SVG 灰色映射到当前
     * 主题前景色，实现亮/暗主题切换时图标自动变色；加载失败降级为「?」文字按钮。
     */
    private JButton buildAboutButton() {
        final Color SVG_BASE = new Color(0x6B, 0x6B, 0x6B);
        JButton btn = new JButton() {
            @Override
            public void updateUI() {
                super.updateUI();
                // 主题切换后重新映射颜色：读取新主题的前景色并替换 SVG 固定灰
                if (getIcon() instanceof FlatSVGIcon) {
                    FlatSVGIcon icon = (FlatSVGIcon) getIcon();
                    Color fg = UIManager.getColor("Label.foreground");
                    FlatSVGIcon.ColorFilter filter = new FlatSVGIcon.ColorFilter();
                    filter.add(SVG_BASE, fg != null ? fg : Color.DARK_GRAY);
                    icon.setColorFilter(filter);
                }
            }
        };
        try {
            FlatSVGIcon icon = new FlatSVGIcon("icons/about.svg", 16, 16);
            btn.setIcon(icon);
        } catch (Exception ignored) {
            // 图标加载失败时降级为文字
            btn.setText("?");
        }
        // FlatLaf 样式属性：无边框无背景，视觉上融入状态栏
        btn.putClientProperty("JButton.buttonType", "borderless");
        btn.setFocusable(false);
        btn.setToolTipText("关于 MemShellParty");
        btn.addActionListener(e -> showAboutDialog());
        return btn;
    }

    private void toggleTheme(boolean dark) {
        // 与 flatlaf-demo 相同：先把旧主题整窗快照盖到 layered pane 上，切换后快照淡出，得到平滑过渡动画
        FlatAnimatedLafChange.showSnapshot();
        if (dark) {
            FlatDarkLaf.setup();
        } else {
            FlatLightLaf.setup();
        }
        FlatLaf.updateUI();
        FlatAnimatedLafChange.hideSnapshotWithAnimation();
        renderActiveStatus();
    }

    MemShellGeneratorFrame memShellFrame() {
        return memShellFrame;
    }

    ProbeGeneratorFrame probeFrame() {
        return probeFrame;
    }

    DecompileFrame decompileFrame() {
        return decompileFrame;
    }

    JTabbedPane pageTabs() {
        return pageTabs;
    }

    JLabel statusLabel() {
        return statusLabel;
    }
}
