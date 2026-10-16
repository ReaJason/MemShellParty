package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import net.miginfocom.swing.MigLayout;

import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Proxy：请求头（仅 BypassNginx 两型可见）。
 */
public class ProxyToolPanel extends AbstractToolPanel {
    private final JPanel headerRow = new JPanel(new MigLayout("insets 0, fillx, gapx 8", "[sg col,grow,fill][sg col,grow,fill]", "[]"));
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public ProxyToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        headerValueField.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        headerRow.add(labeled("请求头名", headerNameField), "growx");
        headerRow.add(labeled("请求头值", headerValueField), "growx");
        add(headerRow, "span 2, growx, wrap, hidemode 3");

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
        headerRow.setVisible(controller.isProxyHeaderVisible());
    }
}
