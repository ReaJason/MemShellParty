package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import net.miginfocom.swing.MigLayout;

import javax.swing.*;

public class GodzillaToolPanel extends AbstractToolPanel {
    private final JTextField passField = new JTextField();
    private final JTextField keyField = new JTextField();
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public GodzillaToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        add(labeled("密码(可选)", passField), "growx");
        add(labeled("密钥(可选)", keyField), "growx, wrap");
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值(可选)", headerValueField), "growx, wrap");
        addRandomClassSection();
        bindText(passField, controller::setGodzillaPass);
        bindText(keyField, controller::setGodzillaKey);
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override
    public void refreshFromController() {
        MemShellFormState s = controller.getState();
        applyCommonState(s);
        updating = true;
        try {
            passField.setText(s.getGodzillaPass());
            keyField.setText(s.getGodzillaKey());
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally { updating = false; }
    }
}
