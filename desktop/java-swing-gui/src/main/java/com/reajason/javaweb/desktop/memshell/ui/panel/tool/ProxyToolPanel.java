package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;

import javax.swing.*;

public class ProxyToolPanel extends AbstractToolPanel {
    private final JPanel headerPanel = new JPanel(new net.miginfocom.swing.MigLayout("insets 0, fillx, gapx 8", "[grow,fill][grow,fill]", "[]"));
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();

    public ProxyToolPanel(MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);
        headerPanel.add(labeled("请求头名", headerNameField), "growx");
        headerPanel.add(labeled("请求头值(可选)", headerValueField), "growx");
        add(headerPanel, "span 2, growx, wrap, hidemode 3");
        addRandomClassSection();
        bindText(headerNameField, controller::setHeaderName);
        bindText(headerValueField, controller::setHeaderValue);
    }

    @Override public void refreshFromController() {
        MemShellFormState s = controller.getState();
        applyCommonState(s);
        updating = true;
        boolean layoutVisibilityChanged = false;
        try {
            boolean nextHeaderVisible = controller.isProxyHeaderVisible();
            if (headerPanel.isVisible() != nextHeaderVisible) {
                layoutVisibilityChanged = true;
            }
            headerPanel.setVisible(nextHeaderVisible);
            headerNameField.setText(s.getHeaderName());
            headerValueField.setText(s.getHeaderValue());
        } finally { updating = false; }
        if (layoutVisibilityChanged) {
            revalidate();
            repaint();
        }
    }
}
