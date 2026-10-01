package com.reajason.javaweb.desktop.memshell.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.formdev.flatlaf.extras.FlatAnimatedLafChange;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.VisibleCardLayout;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.AbstractToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.StatusReporter;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.border.TitledBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GraphicsConfiguration;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.KeyEvent;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 内存马生成器主窗口：顶部「内存马 / 探测马」两页 Tab 共用状态栏。
 * 内存马页为上配置（核心配置 → 内存马功能 → 打包条）/ 下结果（结果 Tab）。
 */
public class MemShellGeneratorFrame extends JFrame {
    private enum Page {
        MEM_SHELL,
        PROBE
    }

    private static final class PageStatus {
        private String message;
        private StatusReporter.Level level;

        private PageStatus(String message, StatusReporter.Level level) {
            this.message = message;
            this.level = level;
        }
    }

    private final MemShellFormController controller;
    private final GenerationService generationService;
    private final MainConfigPanel mainConfigPanel;
    private final PackageConfigPanel packageConfigPanel;
    private final ResultPanel resultPanel;
    private final ProbeShellGeneratorPanel probePanel;
    private final JButton generateButton = new JButton("生成内存马");
    private final JLabel statusLabel = new JLabel("就绪");
    private final PageStatus memShellStatus = new PageStatus("就绪", StatusReporter.Level.INFO);
    private final PageStatus probeStatus = new PageStatus("就绪", StatusReporter.Level.INFO);
    private final JPanel toolCardPanel = new JPanel(new VisibleCardLayout());
    private final Map<String, RefreshableToolPanel> toolPanels = new LinkedHashMap<String, RefreshableToolPanel>();
    private final TitledBorder toolWrapBorder = BorderFactory.createTitledBorder("内存马功能");
    private JComponent mainContentPanel;
    private JTabbedPane pageTabs;
    private AboutDialog aboutDialog;

    public MemShellGeneratorFrame() {
        super("MemShellParty v" + AppVersion.get());
        this.controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        this.generationService = new GenerationService();
        CustomClassNameParser customClassNameParser = new CustomClassNameParser();

        this.resultPanel = new ResultPanel();
        this.probePanel = new ProbeShellGeneratorPanel(this::reportProbeStatus);
        this.mainConfigPanel = new MainConfigPanel(controller, this::refreshAll);
        this.packageConfigPanel = new PackageConfigPanel(controller, this::refreshAll);
        registerToolPanels(customClassNameParser);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        applySizedWindow();
        setLocationRelativeTo(null);
        setJMenuBar(buildMenuBar());

        setLayout(new BorderLayout());
        add(buildContent(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
        resultPanel.setStatusReporter(this::reportMemShellStatus);

        generateButton.setFont(generateButton.getFont().deriveFont(Font.BOLD, 14f));
        // tooltip 同样遵守「拉丁段不被 CJK 夹中间」规则（见 ResultPanel 空态提示的注释）
        generateButton.setToolTipText("生成内存马 (Ctrl/Cmd + Enter)");
        generateButton.addActionListener(e -> onGenerate());
        fixGenerateButtonWidth();
        bindGenerateShortcut();
        resultPanel.clear();
        refreshAll();
    }

    /**
     * 按屏幕可用区域自适应：整体收窄伸长（配置项改为左右布局后不再需要宽屏），
     * 小屏按可用区域收缩，宽高都不超过屏幕可用范围。
     */
    private void applySizedWindow() {
        GraphicsConfiguration config = getGraphicsConfiguration();
        Insets screenInsets = Toolkit.getDefaultToolkit().getScreenInsets(config);
        Dimension screen = config == null ? Toolkit.getDefaultToolkit().getScreenSize() : config.getBounds().getSize();
        int availWidth = screen.width - screenInsets.left - screenInsets.right;
        int availHeight = screen.height - screenInsets.top - screenInsets.bottom;

        int width = Math.min(Math.min(Math.max(availWidth - 80, 940), 1020), availWidth);
        int height = Math.min(Math.min(Math.max(availHeight - 60, 820), 980), availHeight);
        setMinimumSize(new Dimension(Math.min(940, availWidth), Math.min(760, availHeight)));
        setSize(width, height);
    }

    /**
     * Ctrl/⌘ + Enter 任意位置触发生成（按当前页签转发给内存马/探测马）；
     * 裸 Enter 由当前页的默认按钮接管（文本域/下拉/复选框自身消费 Enter，不再出现"勾选即发射"）。
     */
    private void bindGenerateShortcut() {
        // Java 8 Toolkit 只有 getMenuShortcutKeyMask()（Java 9+ 才有 MaskEx 变体）
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, menuMask), "generateShell");
        getRootPane().getActionMap().put("generateShell", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (isProbePageActive()) {
                    probePanel.triggerGenerate();
                } else if (generateButton.isEnabled()) {
                    onGenerate();
                }
            }
        });
        getRootPane().setDefaultButton(generateButton);
    }

    private boolean isProbePageActive() {
        return pageTabs != null && pageTabs.getSelectedComponent() == probePanel;
    }

    private void registerToolPanels(CustomClassNameParser parser) {
        registerToolPanel("Godzilla", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.GodzillaToolPanel(controller, this::refreshAll));
        registerToolPanel("Behinder", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.BehinderToolPanel(controller, this::refreshAll));
        registerToolPanel("AntSword", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.AntSwordToolPanel(controller, this::refreshAll));
        registerToolPanel("Suo5", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.Suo5ToolPanel(controller, this::refreshAll));
        registerToolPanel("Suo5v2", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.Suo5ToolPanel(controller, this::refreshAll));
        registerToolPanel("NeoreGeorg", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.NeoRegToolPanel(controller, this::refreshAll));
        registerToolPanel("Proxy", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.ProxyToolPanel(controller, this::refreshAll));
        registerToolPanel("Command", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.CommandToolPanel(controller, this::refreshAll));
        registerToolPanel("Custom", new com.reajason.javaweb.desktop.memshell.ui.panel.tool.CustomToolPanel(controller, parser, this::refreshAll));
    }

    private void registerToolPanel(String key, RefreshableToolPanel panel) {
        toolPanels.put(key, panel);
        toolCardPanel.add((Component) panel, key);
    }

    /**
     * 菜单栏：帮助 → 关于。FlatLaf 在 macOS 默认启用屏幕菜单栏，菜单进入系统菜单条。
     */
    private JMenuBar buildMenuBar() {
        JMenuBar menuBar = new JMenuBar();
        JMenu helpMenu = new JMenu("帮助");
        JMenuItem aboutItem = new JMenuItem("关于 MemShellParty…");
        aboutItem.addActionListener(e -> showAboutDialog());
        helpMenu.add(aboutItem);
        menuBar.add(helpMenu);
        return menuBar;
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

    private JComponent buildContent() {
        // 内存马页上半：核心配置 → 内存马功能（CardLayout 随工具切换）→ 打包条（分类+变体+生成按钮一行），
        // 纵向堆叠为固定高度的配置区；下半：结果 Tab 占据全部剩余空间（无可拖拽分隔条）
        JPanel toolWrap = new JPanel(new BorderLayout());
        toolWrap.setBorder(toolWrapBorder);
        toolWrap.add(toolCardPanel, BorderLayout.NORTH);

        JPanel packBarInner = new JPanel(new MigLayout("insets 0 4 0 4, fillx, gapx 8", "[grow,fill][]", "[]"));
        packBarInner.add(packageConfigPanel, "growx, pushx");
        packBarInner.add(generateButton, "aligny center, gapright 4");

        JPanel top = new JPanel(new MigLayout("insets 4, fillx, wrap 1", "[grow,fill]", "[]4[]"));
        top.add(mainConfigPanel, "growx");
        top.add(toolWrap, "growx");
        top.add(packBarInner, "growx");

        JPanel content = new JPanel(new BorderLayout(0, 4));
        content.add(top, BorderLayout.NORTH);
        content.add(resultPanel, BorderLayout.CENTER);
        mainContentPanel = content;

        // 顶部页签：内存马 / 探测马，共用底部状态栏；切页时默认按钮（裸 Enter）跟随
        pageTabs = new JTabbedPane();
        pageTabs.addTab("内存马", content);
        pageTabs.addTab("探测马", probePanel);
        pageTabs.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                getRootPane().setDefaultButton(isProbePageActive() ? probePanel.getGenerateButton() : generateButton);
                renderActiveStatus();
            }
        });
        return pageTabs;
    }

    private JComponent buildStatusBar() {
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

        JPanel right = new JPanel(new MigLayout("insets 0, gapx 8", "[][]", "[]"));
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
        JLabel authorLabel = new JLabel("By ReaJason") {
            @Override
            public void updateUI() {
                super.updateUI();
                setForeground(SwingUiUtil.mutedColor());
            }
        };
        right.add(darkToggle);
        right.add(authorLabel);
        p.add(right, BorderLayout.EAST);
        return p;
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

    /**
     * 生成中文案切换（生成内存马 ↔ 生成中…）会改变按钮首选宽度，
     * 打包条里按钮收缩会让左侧打包配置区宽度跟着闪烁；按两种文案最大宽度固定按钮尺寸。
     */
    private void fixGenerateButtonWidth() {
        String original = generateButton.getText();
        int width = 0;
        for (String text : new String[]{"生成内存马", "生成中…"}) {
            generateButton.setText(text);
            width = Math.max(width, generateButton.getPreferredSize().width);
        }
        generateButton.setText(original);
        Dimension size = generateButton.getPreferredSize();
        size.width = width;
        generateButton.setPreferredSize(size);
        generateButton.setMinimumSize(size);
    }

    private void onGenerate() {
        // 快照必须在 EDT 侧拷贝，校验与生成共用同一份：
        // 后台线程读 live state 会与 EDT 上的表单写入竞争（撕裂快照 + TOCTOU）
        final MemShellFormState snapshot = controller.getState().copy();
        clearMemShellFieldErrors();
        MemShellValidator.Result validation = controller.validate(snapshot);
        if (!validation.isValid()) {
            applyValidationErrors(validation.getFieldErrors());
            reportMemShellStatus("校验失败：" + joinMessages(validation), StatusReporter.Level.ERROR);
            focusFirstError(validation);
            return;
        }
        generateButton.setEnabled(false);
        generateButton.setText("生成中…");
        reportMemShellStatus("生成中…", StatusReporter.Level.BUSY);
        final long startTime = System.currentTimeMillis();

        SwingWorker<DesktopMemShellGenerateResult, Void> worker = new SwingWorker<DesktopMemShellGenerateResult, Void>() {
            @Override
            protected DesktopMemShellGenerateResult doInBackground() {
                return generationService.generate(snapshot);
            }

            @Override
            protected void done() {
                generateButton.setEnabled(true);
                generateButton.setText("生成内存马");
                long elapsed = System.currentTimeMillis() - startTime;
                try {
                    DesktopMemShellGenerateResult result = get();
                    resultPanel.showResult(result);
                    reportMemShellStatus("生成成功 · 耗时 " + elapsed + " ms", StatusReporter.Level.SUCCESS);
                } catch (Exception ex) {
                    reportMemShellStatus("生成失败", StatusReporter.Level.ERROR);
                    Throwable cause = ex.getCause() != null ? ex.getCause() : ex;
                    SwingUiUtil.showError(MemShellGeneratorFrame.this, "生成失败: " + cause.getMessage());
                }
            }
        };
        worker.execute();
    }

    /**
     * inline 校验：全部错误一次标完（红描边 + 行内红字），状态栏汇总，焦点跳首个错误字段。
     */
    private void applyValidationErrors(Map<String, String> errors) {
        mainConfigPanel.applyValidationErrors(errors);
        packageConfigPanel.applyValidationErrors(errors);
        RefreshableToolPanel toolPanel = toolPanels.get(controller.getState().getShellTool());
        if (toolPanel instanceof AbstractToolPanel) {
            ((AbstractToolPanel) toolPanel).applyValidationErrors(errors);
        }
    }

    private void focusFirstError(MemShellValidator.Result validation) {
        for (String field : validation.getFieldErrors().keySet()) {
            JComponent target = validationFocusTarget(field);
            if (target != null) {
                target.requestFocusInWindow();
                return;
            }
        }
    }

    private JComponent validationFocusTarget(String field) {
        JComponent target = mainConfigPanel.validationFocusTarget(field);
        if (target == null) {
            target = packageConfigPanel.validationFocusTarget(field);
        }
        if (target == null) {
            RefreshableToolPanel toolPanel = toolPanels.get(controller.getState().getShellTool());
            if (toolPanel instanceof AbstractToolPanel) {
                target = ((AbstractToolPanel) toolPanel).validationFocusTarget(field);
            }
        }
        return target;
    }

    private static String joinMessages(MemShellValidator.Result validation) {
        StringBuilder sb = new StringBuilder();
        for (String message : validation.getFieldErrors().values()) {
            if (sb.length() > 0) {
                sb.append("；");
            }
            sb.append(message);
        }
        return sb.toString();
    }

    private void reportMemShellStatus(String message, StatusReporter.Level level) {
        updatePageStatus(Page.MEM_SHELL, message, level);
    }

    private void reportProbeStatus(String message, StatusReporter.Level level) {
        updatePageStatus(Page.PROBE, message, level);
    }

    private void updatePageStatus(Page page, String message, StatusReporter.Level level) {
        PageStatus pageStatus = page == Page.PROBE ? probeStatus : memShellStatus;
        pageStatus.message = message;
        pageStatus.level = level;
        if (isPageActive(page)) {
            renderActiveStatus();
        }
    }

    private boolean isPageActive(Page page) {
        return page == Page.PROBE ? isProbePageActive() : !isProbePageActive();
    }

    private void renderActiveStatus() {
        PageStatus pageStatus = isProbePageActive() ? probeStatus : memShellStatus;
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

    private void clearMemShellFieldErrors() {
        SwingUiUtil.clearFieldErrors(mainConfigPanel);
        SwingUiUtil.clearFieldErrors(packageConfigPanel);
        for (RefreshableToolPanel panel : toolPanels.values()) {
            if (panel instanceof AbstractToolPanel) {
                SwingUiUtil.clearFieldErrors((AbstractToolPanel) panel);
            }
        }
    }

    public void refreshAll() {
        // 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）
        clearMemShellFieldErrors();
        mainConfigPanel.refreshFromController();
        packageConfigPanel.refreshFromController();
        CardLayout cardLayout = (CardLayout) toolCardPanel.getLayout();
        String shellTool = controller.getState().getShellTool();
        cardLayout.show(toolCardPanel, shellTool);
        // 边框标题跟随当前工具，让功能区与"内存马工具"下拉的联动可见
        toolWrapBorder.setTitle(shellTool == null ? "内存马功能" : "内存马功能 — " + shellTool);
        RefreshableToolPanel toolPanel = toolPanels.get(shellTool);
        if (toolPanel != null) {
            toolPanel.refreshFromController();
        }
        revalidate();
        repaint();
    }

    JComponent getMainContentPanel() {
        return mainContentPanel;
    }

    JButton getGenerateButton() {
        return generateButton;
    }
}
