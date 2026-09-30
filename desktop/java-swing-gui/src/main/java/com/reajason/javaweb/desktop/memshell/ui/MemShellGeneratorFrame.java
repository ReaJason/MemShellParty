package com.reajason.javaweb.desktop.memshell.ui;

import com.formdev.flatlaf.FlatDarkLaf;
import com.formdev.flatlaf.FlatLaf;
import com.formdev.flatlaf.FlatLightLaf;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.AbstractToolPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
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
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.WindowConstants;
import javax.swing.border.TitledBorder;
import java.awt.BorderLayout;
import java.awt.CardLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Container;
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
 * 内存马生成器主窗口：上配置（核心配置 → 内存马功能 → 打包条）/ 下结果（结果 Tab），底部状态栏。
 */
public class MemShellGeneratorFrame extends JFrame {
    private final MemShellFormController controller;
    private final GenerationService generationService;
    private final MainConfigPanel mainConfigPanel;
    private final PackageConfigPanel packageConfigPanel;
    private final ResultPanel resultPanel;
    private final JButton generateButton = new JButton("生成内存马");
    private final JLabel statusLabel = new JLabel("就绪");
    private final JPanel toolCardPanel = new JPanel(new VisibleCardLayout());
    private final Map<String, RefreshableToolPanel> toolPanels = new LinkedHashMap<String, RefreshableToolPanel>();
    private final TitledBorder toolWrapBorder = BorderFactory.createTitledBorder("内存马功能");
    private JComponent mainContentPanel;

    /**
     * CardLayout 的 preferredSize 取所有卡片的最大值（最高的 Custom 卡会撑出大片空白），
     * 这里改为只按当前可见卡片计算，功能区高度随工具切换收紧。
     */
    private static class VisibleCardLayout extends CardLayout {
        private Component current;

        @Override
        public void show(Container parent, String name) {
            super.show(parent, name);
            for (Component c : parent.getComponents()) {
                if (c.isVisible()) {
                    current = c;
                    break;
                }
            }
        }

        @Override
        public Dimension preferredLayoutSize(Container parent) {
            if (current == null) {
                return super.preferredLayoutSize(parent);
            }
            Insets insets = parent.getInsets();
            Dimension d = current.getPreferredSize();
            return new Dimension(d.width + insets.left + insets.right, d.height + insets.top + insets.bottom);
        }

        @Override
        public Dimension minimumLayoutSize(Container parent) {
            return preferredLayoutSize(parent);
        }
    }

    public MemShellGeneratorFrame() {
        super("MemShellParty v" + AppVersion.get());
        this.controller = new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
        this.generationService = new GenerationService();
        CustomClassNameParser customClassNameParser = new CustomClassNameParser();

        this.resultPanel = new ResultPanel();
        this.mainConfigPanel = new MainConfigPanel(controller, this::refreshAll);
        this.packageConfigPanel = new PackageConfigPanel(controller, this::refreshAll);
        registerToolPanels(customClassNameParser);

        setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        applySizedWindow();
        setLocationRelativeTo(null);

        setLayout(new BorderLayout());
        add(buildContent(), BorderLayout.CENTER);
        add(buildStatusBar(), BorderLayout.SOUTH);
        resultPanel.setStatusReporter(this::showStatus);

        generateButton.setFont(generateButton.getFont().deriveFont(Font.BOLD, 14f));
        generateButton.setToolTipText("生成内存马（Ctrl/⌘ + Enter）");
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
     * Ctrl/⌘ + Enter 任意位置触发生成；裸 Enter 由默认按钮接管
     * （文本域/下拉/复选框自身消费 Enter，不再出现"勾选即发射"）。
     */
    private void bindGenerateShortcut() {
        // Java 8 Toolkit 只有 getMenuShortcutKeyMask()（Java 9+ 才有 MaskEx 变体）
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, menuMask), "generateMemshell");
        getRootPane().getActionMap().put("generateMemshell", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (generateButton.isEnabled()) {
                    onGenerate();
                }
            }
        });
        getRootPane().setDefaultButton(generateButton);
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

    private JComponent buildContent() {
        // 上半：核心配置 → 内存马功能（CardLayout 随工具切换）→ 打包条（分类+变体+生成按钮一行），
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
        return content;
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
        if (dark) {
            FlatDarkLaf.setup();
        } else {
            FlatLightLaf.setup();
        }
        FlatLaf.updateUI();
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
        SwingUiUtil.clearFieldErrors(getContentPane());
        MemShellValidator.Result validation = controller.validate(snapshot);
        if (!validation.isValid()) {
            applyValidationErrors(validation.getFieldErrors());
            statusLabel.setForeground(SwingUiUtil.errorColor());
            statusLabel.setText("校验失败：" + joinMessages(validation));
            focusFirstError(validation);
            return;
        }
        generateButton.setEnabled(false);
        generateButton.setText("生成中…");
        statusLabel.setForeground(SwingUiUtil.mutedColor());
        statusLabel.setText("生成中…");
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
                    statusLabel.setForeground(SwingUiUtil.successColor());
                    statusLabel.setText("生成成功 · 耗时 " + elapsed + " ms");
                } catch (Exception ex) {
                    statusLabel.setForeground(SwingUiUtil.errorColor());
                    statusLabel.setText("生成失败");
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

    /**
     * 结果区保存成功等消息走状态栏（中性色，不覆盖成败语义）。
     */
    private void showStatus(String message) {
        statusLabel.setForeground(SwingUiUtil.mutedColor());
        statusLabel.setText(message);
    }

    public void refreshAll() {
        // 结构性变更后旧的错误标记已失真，统一清掉（字段内直接编辑由 bindText 单独清）
        SwingUiUtil.clearFieldErrors(getContentPane());
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
