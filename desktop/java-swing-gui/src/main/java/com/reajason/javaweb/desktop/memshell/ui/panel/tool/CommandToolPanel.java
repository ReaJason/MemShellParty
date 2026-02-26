package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;

public class CommandToolPanel extends AbstractToolPanel {
    private final JPanel paramRow = new JPanel(new MigLayout("insets 0, fillx", "[grow,fill]", "[]"));
    private final JTextField paramField = new JTextField();
    private final JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[grow,fill][grow,fill]", "[]"));
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();
    private final JCheckBox advancedToggle = new JCheckBox("高级配置");
    private final JPanel advancedPanel = new JPanel(new MigLayout("insets 0, fillx, gapx 8, gapy 2, wrap 2", "[grow,fill][grow,fill]", "[]"));
    private final JComboBox<String> encryptorCombo = new JComboBox<>();
    private final JComboBox<String> implCombo = new JComboBox<>();
    private final JTextField commandTemplateField = new JTextField();

    public CommandToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        paramRow.add(labeled("参数名(可选)", paramField), "growx");
        add(paramRow, "span 2, growx, wrap, hidemode 3");

        headerRow.add(labeled("请求头名", headerNameField), "growx");
        headerRow.add(labeled("请求头值(可选)", headerValueField), "growx");
        add(headerRow, "span 2, growx, wrap, hidemode 3");

        add(advancedToggle, "span 2, gapy 2 0, wrap");
        advancedPanel.add(labeled("加密器", encryptorCombo), "growx");
        advancedPanel.add(labeled("实现类", implCombo), "growx");
        advancedPanel.add(labeled("命令模板(可选)", commandTemplateField), "span 2, growx");
        add(advancedPanel, "span 2, growx, wrap, hidemode 3");

        addRandomClassSection();

        bindText(paramField, controller::setCommandParamName);
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
        bindText(commandTemplateField, controller::setCommandTemplate);

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
        advancedToggle.addActionListener(e -> {
            advancedPanel.setVisible(advancedToggle.isSelected());
            revalidate();
            repaint();
        });
    }

    @Override public void refreshFromController() {
        MemShellFormState s = controller.getState();
        applyCommonState(s);
        updating = true;
        boolean layoutVisibilityChanged = false;
        try {
            String encryptor = (s.getEncryptor() == null || s.getEncryptor().trim().isEmpty())
                    ? (controller.getCommandEncryptors().isEmpty() ? null : controller.getCommandEncryptors().get(0))
                    : s.getEncryptor();
            String impl = (s.getImplementationClass() == null || s.getImplementationClass().trim().isEmpty())
                    ? (controller.getCommandImplementationClasses().isEmpty() ? null : controller.getCommandImplementationClasses().get(0))
                    : s.getImplementationClass();
            setComboItems(encryptorCombo, controller.getCommandEncryptors(), encryptor);
            setComboItems(implCombo, controller.getCommandImplementationClasses(), impl);
            boolean nextParamVisible = controller.isCommandParamVisible();
            boolean nextHeaderVisible = controller.isCommandHeaderVisible();
            if (paramRow.isVisible() != nextParamVisible) {
                layoutVisibilityChanged = true;
            }
            if (headerRow.isVisible() != nextHeaderVisible) {
                layoutVisibilityChanged = true;
            }
            paramRow.setVisible(nextParamVisible);
            headerRow.setVisible(nextHeaderVisible);
            paramField.setText(s.getCommandParamName());
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
            commandTemplateField.setText(s.getCommandTemplate());
            boolean nextAdvancedVisible = advancedToggle.isSelected();
            if (advancedPanel.isVisible() != nextAdvancedVisible) {
                layoutVisibilityChanged = true;
            }
            advancedPanel.setVisible(nextAdvancedVisible);
        } finally { updating = false; }
        if (layoutVisibilityChanged) {
            revalidate();
            repaint();
        }
    }
}
