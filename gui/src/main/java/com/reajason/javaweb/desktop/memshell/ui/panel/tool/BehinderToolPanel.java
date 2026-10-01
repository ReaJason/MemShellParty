package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.JTextField;

/**
 * Behinder：连接密码 / 请求头。
 */
public class BehinderToolPanel extends AbstractToolPanel {
    private final JTextField passField = new JTextField();
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public BehinderToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        passField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        headerValueField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        add(labeled("连接密码", passField), "growx");
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值", headerValueField), "growx, wrap");

        bindText(passField, controller::setBehinderPass);
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override
    public void refreshFromController() {
        super.refreshFromController();
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            passField.setText(s.getBehinderPass());
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally {
            updating = false;
        }
    }
}
