package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.*;

public class NeoRegToolPanel extends AbstractToolPanel {
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public NeoRegToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值(可选)", headerValueField), "growx, wrap");
        addRandomClassSection();
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override public void refreshFromController() {
        MemShellFormState s = controller.getState();
        applyCommonState(s);
        updating = true;
        try {
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally { updating = false; }
    }
}
