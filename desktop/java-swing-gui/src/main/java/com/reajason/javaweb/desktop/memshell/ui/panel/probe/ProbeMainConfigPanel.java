package com.reajason.javaweb.desktop.memshell.ui.panel.probe;

import com.reajason.javaweb.desktop.memshell.controller.ProbeShellFormController;
import com.reajason.javaweb.desktop.memshell.model.ProbeShellFormState;
import com.reajason.javaweb.desktop.memshell.ui.panel.VisibleCardLayout;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JList;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.util.List;
import java.util.Map;

/**
 * 探测马配置：探测方式/JRE 两下拉 + 探测内容 + 方式相关条件行（目标服务/DNSLog 域名/休眠服务）
 * + 内容相关条件行（参数名/命令模板/休眠秒数）+ 探测马类名 + 五个开关。
 * 方式相关行用 {@link VisibleCardLayout} 卡片切换，高度随当前卡片收紧；
 * 内容相关行共用一张参数卡，命令模板行按内容显隐（hidemode 3 不占位）。
 */
public class ProbeMainConfigPanel extends JPanel {
    private final ProbeShellFormController controller;
    private final Runnable refreshAll;
    private boolean updating;

    private final JComboBox<String> methodCombo = new JComboBox<String>();
    private final JComboBox<String> targetJdkCombo = new JComboBox<String>();
    private final JComboBox<String> serverCombo = new JComboBox<String>();
    private final JComboBox<String> contentCombo = new JComboBox<String>();
    private final JComboBox<String> sleepServerCombo = new JComboBox<String>();
    private final JTextField hostField = new JTextField();
    private final JTextField secondsField = new JTextField();
    private final JTextField reqParamNameField = new JTextField();
    private final JTextField commandTemplateField = new JTextField();
    private final JTextField shellClassNameField = new JTextField();

    private final JCheckBox debugCheck = new JCheckBox("调试模式");
    private final JCheckBox bypassCheck = new JCheckBox("绕过模块限制");
    private final JCheckBox lambdaCheck = new JCheckBox("Lambda 类名后缀");
    private final JCheckBox shrinkCheck = new JCheckBox("缩小字节码");
    private final JCheckBox staticInitCheck = new JCheckBox("静态初始化");

    private final JPanel methodCardPanel = new JPanel(new VisibleCardLayout());
    private final JPanel contentCardPanel = new JPanel(new VisibleCardLayout());
    private JPanel commandTemplateRow;

    public ProbeMainConfigPanel(ProbeShellFormController controller, Runnable refreshAll) {
        this.controller = controller;
        this.refreshAll = refreshAll;
        setLayout(new MigLayout("insets 8, fillx, gapx 8, gapy 4, wrap 2", "[sg col,grow,fill][sg col,grow,fill]", "[]4[]"));
        setBorder(BorderFactory.createTitledBorder("探测马配置"));

        add(labeled("探测方式", methodCombo), "growx");
        add(labeled("JRE 版本", targetJdkCombo), "growx");

        // 方式相关行（左列卡片）：ResponseBody → 目标服务；DNSLog → 域名；Sleep → 休眠服务
        methodCardPanel.add(labeled("目标服务", serverCombo), "ResponseBody");
        methodCardPanel.add(labeled("DNSLog 域名", hostField), "DNSLog");
        methodCardPanel.add(labeled("休眠服务", sleepServerCombo), "Sleep");
        add(methodCardPanel, "growx");
        add(labeled("探测内容", contentCombo), "growx");

        // 内容相关行（整行卡片）：参数名（+命令模板）/ 休眠秒数 / 无
        contentCardPanel.add(buildParamCard(), "param");
        contentCardPanel.add(labeled("休眠秒数", secondsField), "seconds");
        contentCardPanel.add(new JPanel(), "none");
        add(contentCardPanel, "span 2, growx, wrap");

        shellClassNameField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        add(labeled("探测马类名", shellClassNameField), "span 2, growx, wrap");

        JPanel togglePanel = new JPanel(new MigLayout("insets 0, gapx 12, gapy 2", "[][][][][]push", "[]"));
        togglePanel.add(debugCheck);
        togglePanel.add(bypassCheck);
        togglePanel.add(lambdaCheck);
        togglePanel.add(shrinkCheck);
        togglePanel.add(staticInitCheck);
        add(togglePanel, "span 2, growx, wrap");

        hostField.putClientProperty("JTextField.placeholderText", "如 xxx.dnslog.cn");
        reqParamNameField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        commandTemplateField.putClientProperty("JTextField.placeholderText", "如 sh -c {command}，留空则直接执行");

        debugCheck.setToolTipText("输出调试日志");
        bypassCheck.setToolTipText("绕过模块系统限制（自动勾选），适用于 JDK 9+");
        lambdaCheck.setToolTipText("Lambda 后缀可规避部分内存马查杀");
        shrinkCheck.setToolTipText("缩小生成字节码体积");
        staticInitCheck.setToolTipText("使用静态初始化触发探测逻辑");

        bindText(hostField, controller::setHost);
        bindText(secondsField, controller::setSeconds);
        bindText(reqParamNameField, controller::setReqParamName);
        bindText(commandTemplateField, controller::setCommandTemplate);
        bindText(shellClassNameField, controller::setShellClassName);

        methodCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(methodCombo);
            Object item = methodCombo.getSelectedItem();
            if (item != null) {
                controller.setProbeMethod(String.valueOf(item));
                refreshAll.run();
            }
        });
        contentCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(contentCombo);
            Object item = contentCombo.getSelectedItem();
            if (item != null) {
                controller.setProbeContent(String.valueOf(item));
                refreshAll.run();
            }
        });
        serverCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(serverCombo);
            Object item = serverCombo.getSelectedItem();
            if (item != null) controller.setServer(String.valueOf(item));
        });
        sleepServerCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(sleepServerCombo);
            Object item = sleepServerCombo.getSelectedItem();
            if (item != null) controller.setSleepServer(String.valueOf(item));
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
        bypassCheck.addActionListener(e -> controller.setByPassJavaModule(bypassCheck.isSelected()));
        lambdaCheck.addActionListener(e -> controller.setLambdaSuffix(lambdaCheck.isSelected()));
        shrinkCheck.addActionListener(e -> controller.setShrink(shrinkCheck.isSelected()));
        staticInitCheck.addActionListener(e -> controller.setStaticInitialize(staticInitCheck.isSelected()));
    }

    /**
     * 参数卡：参数名恒显，命令模板仅 Command 内容可见（对齐 web probeshell/main-config-card）。
     * 文本组件只能有一个父容器，两张卡不能共享字段，故模板行用显隐而非独立卡片。
     */
    private JPanel buildParamCard() {
        JPanel card = new JPanel(new MigLayout("insets 0, fillx, gapy 4, wrap 1", "[grow,fill]", "[][]"));
        card.add(labeled("参数名（可选）", reqParamNameField), "growx");
        commandTemplateRow = labeled("命令模板（可选）", commandTemplateField);
        card.add(commandTemplateRow, "growx, hidemode 3");
        return card;
    }

    public void refreshFromController() {
        ProbeShellFormState s = controller.getState();
        updating = true;
        try {
            setComboItems(methodCombo, controller.getProbeMethods(), s.getProbeMethod());
            setComboItems(serverCombo, controller.getResponseBodyServers(), s.getServer());
            setComboItems(sleepServerCombo, controller.getSleepServers(), s.getSleepServer());
            setComboItems(contentCombo, controller.getProbeContents(), s.getProbeContent());
            setJdkComboItems(s.getTargetJdkVersion());

            hostField.setText(s.getHost());
            secondsField.setText(s.getSeconds());
            reqParamNameField.setText(s.getReqParamName());
            commandTemplateField.setText(s.getCommandTemplate());
            shellClassNameField.setText(s.getShellClassName());

            debugCheck.setSelected(s.isDebug());
            bypassCheck.setSelected(s.isByPassJavaModule());
            lambdaCheck.setSelected(s.isLambdaSuffix());
            shrinkCheck.setSelected(s.isShrink());
            staticInitCheck.setSelected(s.isStaticInitialize());

            ((VisibleCardLayout) methodCardPanel.getLayout()).show(methodCardPanel, s.getProbeMethod());
            ((VisibleCardLayout) contentCardPanel.getLayout()).show(contentCardPanel, contentCard(s));
            commandTemplateRow.setVisible("ResponseBody".equals(s.getProbeMethod()) && "Command".equals(s.getProbeContent()));
        } finally {
            updating = false;
        }
        revalidate();
        repaint();
    }

    /**
     * 内容相关卡片选择（对齐 web probeshell/main-config-card 的可见性规则）：
     * ResponseBody + Command/Bytecode/ScriptEngine → 参数卡；Sleep + Server → 休眠秒数；其余无附加项。
     */
    private static String contentCard(ProbeShellFormState s) {
        String method = s.getProbeMethod();
        String content = s.getProbeContent();
        if ("ResponseBody".equals(method)) {
            if ("Command".equals(content) || "Bytecode".equals(content) || "ScriptEngine".equals(content)) {
                return "param";
            }
            return "none";
        }
        if ("Sleep".equals(method) && "Server".equals(content)) {
            return "seconds";
        }
        return "none";
    }

    /**
     * JRE 下拉显示 "Java 8 (52)" 标签，state 存原值。
     */
    private void setJdkComboItems(String selected) {
        List<String> options = controller.getCatalogService().getTargetJdkOptions();
        targetJdkCombo.removeAllItems();
        for (String option : options) {
            targetJdkCombo.addItem(option);
        }
        targetJdkCombo.setSelectedItem(selected);
        targetJdkCombo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index, boolean isSelected, boolean cellHasFocus) {
                super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                if (value != null) {
                    setText(controller.getCatalogService().getTargetJdkLabel(String.valueOf(value)) + " (" + value + ")");
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
    public void applyValidationErrors(Map<String, String> errors) {
        applyError(errors, "probeMethod", methodCombo);
        applyError(errors, "probeContent", contentCombo);
        applyError(errors, "server", serverCombo);
        applyError(errors, "host", hostField);
        applyError(errors, "sleepServer", sleepServerCombo);
        applyError(errors, "seconds", secondsField);
    }

    private void applyError(Map<String, String> errors, String field, JComponent component) {
        String message = errors.get(field);
        if (message != null) {
            SwingUiUtil.setFieldError(component, message);
        }
    }

    /**
     * 校验失败时焦点跳转目标；字段不属于本面板返回 null。
     */
    public JComponent validationFocusTarget(String field) {
        if ("probeMethod".equals(field)) return methodCombo;
        if ("probeContent".equals(field)) return contentCombo;
        if ("server".equals(field)) return serverCombo;
        if ("host".equals(field)) return hostField;
        if ("sleepServer".equals(field)) return sleepServerCombo;
        if ("seconds".equals(field)) return secondsField;
        return null;
    }
}
