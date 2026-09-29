package com.reajason.javaweb.desktop.memshell.ui;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.service.GenerationService;
import com.reajason.javaweb.desktop.memshell.ui.panel.MainConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.PackageConfigPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.ResultPanel;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.RefreshableToolPanel;
import com.reajason.javaweb.desktop.memshell.util.AppVersion;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import net.miginfocom.swing.MigLayout;

import javax.swing.AbstractAction;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComponent;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.KeyStroke;
import javax.swing.SwingWorker;
import javax.swing.WindowConstants;
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
     * Ctrl/⌘ + Enter 任意位置触发生成；Enter 在默认按钮不可用时仍是快捷路径。
     */
    private void bindGenerateShortcut() {
        // Java 8 Toolkit 只有 getMenuShortcutKeyMask()（Java 9+ 才有 MaskEx 变体）
        int menuMask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMask();
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, menuMask), "generateMemshell");
        getRootPane().getInputMap(JComponent.WHEN_IN_FOCUSED_WINDOW)
                .put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "generateMemshell");
        getRootPane().getActionMap().put("generateMemshell", new AbstractAction() {
            @Override
            public void actionPerformed(ActionEvent e) {
                if (generateButton.isEnabled()) {
                    onGenerate();
                }
            }
        });
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
        toolWrap.setBorder(BorderFactory.createTitledBorder("内存马功能"));
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
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, new Color(200, 200, 200)),
                BorderFactory.createEmptyBorder(3, 8, 3, 8)));
        p.add(statusLabel, BorderLayout.WEST);
        JLabel authorLabel = new JLabel("By ReaJason");
        authorLabel.setForeground(SwingUiUtil.mutedColor());
        p.add(authorLabel, BorderLayout.EAST);
        return p;
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
        MemShellValidator.Result validation = controller.validate();
        if (!validation.isValid()) {
            statusLabel.setForeground(SwingUiUtil.errorColor());
            statusLabel.setText("校验失败");
            SwingUiUtil.showError(this, validation.firstMessage());
            return;
        }
        generateButton.setEnabled(false);
        generateButton.setText("生成中…");
        statusLabel.setForeground(SwingUiUtil.mutedColor());
        statusLabel.setText("生成中...");
        final long startTime = System.currentTimeMillis();

        SwingWorker<DesktopMemShellGenerateResult, Void> worker = new SwingWorker<DesktopMemShellGenerateResult, Void>() {
            @Override
            protected DesktopMemShellGenerateResult doInBackground() {
                return generationService.generate(controller.getState().copy());
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

    public void refreshAll() {
        mainConfigPanel.refreshFromController();
        packageConfigPanel.refreshFromController();
        CardLayout cardLayout = (CardLayout) toolCardPanel.getLayout();
        cardLayout.show(toolCardPanel, controller.getState().getShellTool());
        RefreshableToolPanel toolPanel = toolPanels.get(controller.getState().getShellTool());
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
