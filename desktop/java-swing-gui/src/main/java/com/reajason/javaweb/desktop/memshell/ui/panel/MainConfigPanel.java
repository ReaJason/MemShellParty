package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.util.List;

/**
 * ① 核心配置：服务/版本/工具/JRE 四下拉 + 内存马/注入器类名（留空随机生成）+ 六个开关。
 */
public class MainConfigPanel extends JPanel {
    private final MemShellFormController controller;
    private final Runnable refreshAll;
    private boolean updating;

    private final JComboBox<String> serverCombo = new JComboBox<String>();
    private final JComboBox<String> serverVersionCombo = new JComboBox<String>();
    private final JComboBox<String> shellToolCombo = new JComboBox<String>();
    private final JComboBox<String> targetJdkCombo = new JComboBox<String>();
    private final JTextField shellClassNameField = new JTextField();
    private final JTextField injectorClassNameField = new JTextField();

    private final JCheckBox debugCheck = new JCheckBox("调试模式");
    private final JCheckBox probeCheck = new JCheckBox("回显模式");
    private final JCheckBox bypassCheck = new JCheckBox("绕过模块限制");
    private final JCheckBox lambdaCheck = new JCheckBox("Lambda 类名后缀");
    private final JCheckBox shrinkCheck = new JCheckBox("缩小字节码");
    private final JCheckBox staticInitCheck = new JCheckBox("静态初始化");

    public MainConfigPanel(MemShellFormController controller, Runnable refreshAll) {
        this.controller = controller;
        this.refreshAll = refreshAll;
        setLayout(new MigLayout("insets 8, fillx, gapx 8, gapy 4, wrap 2", "[sg col,grow,fill][sg col,grow,fill]", "[]4[]"));
        setBorder(BorderFactory.createTitledBorder("核心配置"));

        add(labeled("服务类型", serverCombo), "growx");
        add(labeled("服务版本", serverVersionCombo), "growx");
        add(labeled("内存马工具", shellToolCombo), "growx");
        add(labeled("JRE 版本", targetJdkCombo), "growx");

        shellClassNameField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        injectorClassNameField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        add(labeled("内存马类名", shellClassNameField), "growx");
        add(labeled("注入器类名", injectorClassNameField), "growx");

        JPanel togglePanel = new JPanel(new MigLayout("insets 0, gapx 12, gapy 2", "[][][][][][]push", "[]"));
        togglePanel.add(debugCheck);
        togglePanel.add(probeCheck);
        togglePanel.add(bypassCheck);
        togglePanel.add(lambdaCheck);
        togglePanel.add(shrinkCheck);
        togglePanel.add(staticInitCheck);
        add(togglePanel, "span 2, growx, wrap");

        debugCheck.setToolTipText("输出调试日志");
        probeCheck.setToolTipText("回显模式：注入后通过响应回显探测");
        bypassCheck.setToolTipText("绕过 JDK 9+ 模块系统限制（JDK ≥ 9 自动勾选）");
        lambdaCheck.setToolTipText("追加 Lambda 后缀规避部分内存马查杀");
        shrinkCheck.setToolTipText("缩小生成字节码体积");
        staticInitCheck.setToolTipText("注入器使用静态初始化触发");

        bindText(shellClassNameField, controller::setShellClassName);
        bindText(injectorClassNameField, controller::setInjectorClassName);

        serverCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(serverCombo);
            Object item = serverCombo.getSelectedItem();
            if (item != null) {
                controller.setServer(String.valueOf(item));
                refreshAll.run();
            }
        });
        serverVersionCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(serverVersionCombo);
            Object item = serverVersionCombo.getSelectedItem();
            if (item != null) controller.setServerVersion(String.valueOf(item));
        });
        shellToolCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(shellToolCombo);
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
            setJdkComboItems(s.getTargetJdkVersion());
            shellClassNameField.setText(s.getShellClassName());
            injectorClassNameField.setText(s.getInjectorClassName());

            debugCheck.setSelected(s.isDebug());
            probeCheck.setSelected(s.isProbe());
            bypassCheck.setSelected(s.isByPassJavaModule());
            lambdaCheck.setSelected(s.isLambdaSuffix());
            shrinkCheck.setSelected(s.isShrink());
            staticInitCheck.setSelected(s.isStaticInitialize());
        } finally {
            updating = false;
        }
    }

    /**
     * JRE 下拉显示 "Java 8 (52)" 标签，state 存原值。
     */
    private void setJdkComboItems(String selected) {
        List<String> options = controller.getConfigCatalogService().getTargetJdkOptions();
        targetJdkCombo.removeAllItems();
        for (String option : options) {
            targetJdkCombo.addItem(option);
        }
        targetJdkCombo.setSelectedItem(selected);
        targetJdkCombo.setRenderer(new javax.swing.DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(javax.swing.JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value != null) {
                    setText(controller.getConfigCatalogService().getTargetJdkLabel(String.valueOf(value)) + " (" + value + ")");
                }
                return this;
            }
        });
    }

    private JPanel labeled(String label, JComponent component) {
        return SwingUiUtil.labeled(label, component);
    }

    private void setComboItems(JComboBox<String> combo, List<String> items, String selected) {
        combo.removeAllItems();
        for (String item : items) {
            combo.addItem(item);
        }
        if (selected != null) {
            combo.setSelectedItem(selected);
        }
    }

    private void bindText(JTextField field, java.util.function.Consumer<String> setter) {
        field.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                changed();
            }

            private void changed() {
                if (updating) return;
                SwingUiUtil.clearFieldError(field);
                setter.accept(field.getText());
            }
        });
    }

    /**
     * inline 校验：把属于本面板的字段错误标到对应行（红描边 + 行内红字）。
     */
    public void applyValidationErrors(java.util.Map<String, String> errors) {
        applyError(errors, "server", serverCombo);
        applyError(errors, "serverVersion", serverVersionCombo);
        applyError(errors, "shellTool", shellToolCombo);
    }

    private void applyError(java.util.Map<String, String> errors, String field, JComponent component) {
        String message = errors.get(field);
        if (message != null) {
            SwingUiUtil.setFieldError(component, message);
        }
    }

    /**
     * 校验失败时焦点跳转目标；字段不属于本面板返回 null。
     */
    public JComponent validationFocusTarget(String field) {
        if ("server".equals(field)) return serverCombo;
        if ("serverVersion".equals(field)) return serverVersionCombo;
        if ("shellTool".equals(field)) return shellToolCombo;
        return null;
    }
}
