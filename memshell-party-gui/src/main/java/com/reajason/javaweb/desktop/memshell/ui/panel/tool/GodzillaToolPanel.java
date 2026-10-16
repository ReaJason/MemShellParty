package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.JTextField;

/**
 * Godzilla：密码 / 密钥 / 请求头名 / 请求头值（dev API 无加密器字段，仅在结果区展示派生加密器）。
 */
public class GodzillaToolPanel extends AbstractToolPanel {
    private final JTextField passField = new JTextField();
    private final JTextField keyField = new JTextField();
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public GodzillaToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        passField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        keyField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        headerValueField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        add(labeled("密码", passField), "growx");
        add(labeled("密钥", keyField), "growx");
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值", headerValueField), "growx, wrap");

        bindText(passField, controller::setGodzillaPass);
        bindText(keyField, controller::setGodzillaKey);
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override
    public void refreshFromController() {
        super.refreshFromController();
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            passField.setText(s.getGodzillaPass());
            keyField.setText(s.getGodzillaKey());
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally {
            updating = false;
        }
    }
}
