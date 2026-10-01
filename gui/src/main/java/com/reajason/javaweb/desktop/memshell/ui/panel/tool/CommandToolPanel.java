package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import net.miginfocom.swing.MigLayout;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Font;

/**
 * Command：参数名 / 请求头（按挂载类型显隐）/ 折叠高级配置（加密器 · 实现类 · 命令模板）。
 */
public class CommandToolPanel extends AbstractToolPanel {
    private final JPanel paramRow = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
    private final JTextField paramField = new JTextField();
    private final JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[sg col,grow,fill][sg col,grow,fill]", "[]"));
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();
    private final JCheckBox advancedToggle = new JCheckBox("高级配置");
    private final JPanel advancedPanel = new JPanel(new MigLayout("insets 4 8 0 8, fillx, gapx 8, gapy 2, wrap 2", "[sg col,grow,fill][sg col,grow,fill]", "[]"));
    private final JComboBox<String> encryptorCombo = new JComboBox<String>();
    private final JComboBox<String> implCombo = new JComboBox<String>();
    private final JTextField commandTemplateField = new JTextField();

    public CommandToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        paramField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        headerValueField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        commandTemplateField.putClientProperty("JTextField.placeholderText", "留空则直接执行命令");
        paramRow.add(labeled("参数名", paramField), "growx");
        add(paramRow, "span 2, growx, wrap, hidemode 3");

        headerRow.add(labeled("请求头名", headerNameField), "growx");
        headerRow.add(labeled("请求头值", headerValueField), "growx");
        add(headerRow, "span 2, growx, wrap, hidemode 3");

        add(advancedToggle, "span 2, gapy 2 0, wrap");
        advancedPanel.add(labeled("加密器", encryptorCombo), "growx");
        advancedPanel.add(labeled("实现类", implCombo), "growx");
        advancedPanel.add(labeled("命令模板", commandTemplateField), "span 2, growx");
        JLabel hint = new JLabel("如 sh -c \"{command}\" 2>&1");
        hint.setFont(hint.getFont().deriveFont(Font.PLAIN, 11f));
        advancedPanel.add(hint, "span 2, growx, wrap");
        advancedPanel.setVisible(false);
        add(advancedPanel, "span 2, growx, wrap, hidemode 3");

        bindText(paramField, controller::setCommandParamName);
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
        bindText(commandTemplateField, controller::setCommandTemplate);

        advancedToggle.addActionListener(e -> advancedPanel.setVisible(advancedToggle.isSelected()));

        encryptorCombo.addActionListener(e -> {
            if (updating) return;
            Object item = encryptorCombo.getSelectedItem();
            controller.setEncryptor(item == null ? "" : String.valueOf(item));
        });
        implCombo.addActionListener(e -> {
            if (updating) return;
            Object item = implCombo.getSelectedItem();
            controller.setImplementationClass(item == null ? "" : String.valueOf(item));
        });

    }

    @Override
    public void refreshFromController() {
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            setComboItems(encryptorCombo, controller.getCommandEncryptors(), s.getEncryptor());
            setComboItems(implCombo, controller.getCommandImplementationClasses(), s.getImplementationClass());
            applyCommonState(s);
            paramField.setText(s.getCommandParamName());
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
            commandTemplateField.setText(s.getCommandTemplate());
        } finally {
            updating = false;
        }
        paramRow.setVisible(controller.isCommandParamVisible());
        headerRow.setVisible(controller.isCommandHeaderVisible());
    }
}
