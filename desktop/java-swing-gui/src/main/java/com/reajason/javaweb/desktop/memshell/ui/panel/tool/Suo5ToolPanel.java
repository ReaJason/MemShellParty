package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.JTextField;

/**
 * Suo5 / Suo5v2：自定义请求头。
 */
public class Suo5ToolPanel extends AbstractToolPanel {
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public Suo5ToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        headerValueField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值", headerValueField), "growx, wrap");

        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override
    public void refreshFromController() {
        super.refreshFromController();
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally {
            updating = false;
        }
    }
}
