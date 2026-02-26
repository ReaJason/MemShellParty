package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.service.CustomClassNameParser;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.*;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;
import java.awt.*;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class MainConfigPanel extends JPanel {
    private final MemShellFormController controller;
    private final Runnable refreshAll;
    private boolean updating;

    private final JComboBox<String> serverCombo = new JComboBox<>();
    private final JComboBox<String> serverVersionCombo = new JComboBox<>();
    private final JComboBox<String> shellToolCombo = new JComboBox<>();
    private final JComboBox<String> targetJdkCombo = new JComboBox<>();

    private final JCheckBox debugCheck = new JCheckBox("调试模式");
    private final JCheckBox probeCheck = new JCheckBox("回显模式");
    private final JCheckBox bypassCheck = new JCheckBox("绕过模块限制");
    private final JCheckBox lambdaCheck = new JCheckBox("Lambda 类名后缀");
    private final JCheckBox shrinkCheck = new JCheckBox("缩小字节码");
    private final JCheckBox staticInitCheck = new JCheckBox("静态初始化");

    private final JPanel corePanel;
    private final JPanel toolPanelWrap;
    private final JPanel toolCardPanel = new JPanel(new CardLayout());
    private final Map<String, RefreshableToolPanel> toolPanels = new LinkedHashMap<>();

    public MainConfigPanel(MemShellFormController controller, CustomClassNameParser parser, Runnable refreshAll) {
        super(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]6[]"));
        this.controller = controller;
        this.refreshAll = refreshAll;

        corePanel = new JPanel(new MigLayout("insets 8, fillx, gapx 8, gapy 2, wrap 2", "[grow,fill][grow,fill]", "[]4[]"));
        corePanel.setBorder(BorderFactory.createTitledBorder("核心配置"));
        corePanel.add(labeled("服务类型", serverCombo), "growx");
        corePanel.add(labeled("服务版本", serverVersionCombo), "growx");
        corePanel.add(labeled("内存马工具", shellToolCombo), "growx");
        corePanel.add(labeled("JRE 版本", targetJdkCombo), "growx");

        JPanel togglePanel = new JPanel(new MigLayout("insets 0, gapx 8, gapy 2, wrap 3", "[grow,fill][grow,fill][grow,fill]", "[]"));
        togglePanel.add(debugCheck);
        togglePanel.add(probeCheck);
        togglePanel.add(bypassCheck);
        togglePanel.add(lambdaCheck);
        togglePanel.add(shrinkCheck);
        togglePanel.add(staticInitCheck);
        corePanel.add(togglePanel, "span 2, growx");
        add(corePanel, "growx");

        toolPanelWrap = new JPanel(new BorderLayout());
        toolPanelWrap.setBorder(BorderFactory.createTitledBorder("内存马功能"));
        // Keep the active tool panel at preferred height to avoid large blank sections.
        toolPanelWrap.add(toolCardPanel, BorderLayout.NORTH);
        add(toolPanelWrap, "growx");

        registerToolPanel("Godzilla", new GodzillaToolPanel(controller, refreshAll));
        registerToolPanel("Command", new CommandToolPanel(controller, refreshAll));
        registerToolPanel("Behinder", new BehinderToolPanel(controller, refreshAll));
        registerToolPanel("AntSword", new AntSwordToolPanel(controller, refreshAll));
        registerToolPanel("Suo5", new Suo5ToolPanel(controller, refreshAll));
        registerToolPanel("Suo5v2", new Suo5ToolPanel(controller, refreshAll));
        registerToolPanel("NeoreGeorg", new NeoRegToolPanel(controller, refreshAll));
        registerToolPanel("Proxy", new ProxyToolPanel(controller, refreshAll));
        registerToolPanel("Custom", new CustomToolPanel(controller, parser, refreshAll));

        bindEvents();
    }

    private void registerToolPanel(String key, RefreshableToolPanel panel) {
        toolPanels.put(key, panel);
        toolCardPanel.add((Component) panel, key);
    }

    private JPanel labeled(String label, JComponent component) {
        JPanel p = new JPanel(new MigLayout("insets 0, fillx, wrap 1", "[grow,fill]", "[]1[]"));
        p.add(new JLabel(label));
        p.add(component, "growx");
        return p;
    }

    private void bindEvents() {
        serverCombo.addActionListener(e -> {
            if (updating) return;
            Object item = serverCombo.getSelectedItem();
            if (item != null) {
                controller.setServer(String.valueOf(item));
                refreshAll.run();
            }
        });
        serverVersionCombo.addActionListener(e -> {
            if (updating) return;
            Object item = serverVersionCombo.getSelectedItem();
            if (item != null) controller.setServerVersion(String.valueOf(item));
        });
        shellToolCombo.addActionListener(e -> {
            if (updating) return;
            Object item = shellToolCombo.getSelectedItem();
            if (item != null) {
                controller.setShellTool(String.valueOf(item));
                refreshAll.run();
            }
        });
        targetJdkCombo.addActionListener(e -> {
            if (updating) return;
            Object item = targetJdkCombo.getSelectedItem();
            if (item != null) {
                controller.setTargetJdkVersion(String.valueOf(item));
                refreshAll.run();
            }
        });

        debugCheck.addActionListener(e -> controller.setDebug(debugCheck.isSelected()));
        probeCheck.addActionListener(e -> controller.setProbe(probeCheck.isSelected()));
        bypassCheck.addActionListener(e -> controller.setByPassJavaModule(bypassCheck.isSelected()));
        lambdaCheck.addActionListener(e -> controller.setLambdaSuffix(lambdaCheck.isSelected()));
        shrinkCheck.addActionListener(e -> controller.setShrink(shrinkCheck.isSelected()));
        staticInitCheck.addActionListener(e -> controller.setStaticInitialize(staticInitCheck.isSelected()));
    }

    public void refreshFromController() {
        MemShellFormState s = controller.getState();
        updating = true;
        try {
            setComboItems(serverCombo, controller.getServers(), s.getServer());
            setComboItems(serverVersionCombo, controller.getServerVersionOptions(), s.getServerVersion());
            setComboItems(shellToolCombo, controller.getShellTools(), s.getShellTool());
            setComboItems(targetJdkCombo, controller.getConfigCatalogService().getTargetJdkOptions(), s.getTargetJdkVersion());

            debugCheck.setSelected(s.isDebug());
            probeCheck.setSelected(s.isProbe());
            bypassCheck.setSelected(s.isByPassJavaModule());
            lambdaCheck.setSelected(s.isLambdaSuffix());
            shrinkCheck.setSelected(s.isShrink());
            staticInitCheck.setSelected(s.isStaticInitialize());
        } finally {
            updating = false;
        }

        CardLayout cardLayout = (CardLayout) toolCardPanel.getLayout();
        cardLayout.show(toolCardPanel, s.getShellTool());
        RefreshableToolPanel toolPanel = toolPanels.get(s.getShellTool());
        if (toolPanel != null) {
            toolPanel.refreshFromController();
        }
    }

    private void setComboItems(JComboBox<String> combo, List<String> items, String selected) {
        combo.removeAllItems();
        for (String item : items) combo.addItem(item);
        if (selected != null) combo.setSelectedItem(selected);
    }

    public JComponent getCorePanelComponent() {
        return corePanel;
    }

    public JComponent getToolPanelComponent() {
        return toolPanelWrap;
    }
}
