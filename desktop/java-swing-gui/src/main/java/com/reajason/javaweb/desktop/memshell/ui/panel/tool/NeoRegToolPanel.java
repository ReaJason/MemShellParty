package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.JTextField;

/**
 * NeoreGeorg：自定义请求头（切工具时控制器已置 headerName=Referer）。
 */
public class NeoRegToolPanel extends AbstractToolPanel {
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public NeoRegToolPanel(MemShellFormController controller, Runnable refreshAll) {
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
