package com.reajason.javaweb.examples.customgui.gui;

import com.reajason.javaweb.desktop.memshell.extension.ToolPanelContext;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.ui.panel.tool.AbstractToolPanel;

import javax.swing.JTextField;

/**
 * 自定义 shelltool（{@code GodzillaSession}）的专用参数面板：字段和通用面板一样，只是文案、
 * 排序、提示都由自己说了算。
 *
 * <p>继承 {@link AbstractToolPanel} 就自带「内存马挂载类型 + 请求路径」两个公共字段，
 * 参数读写走 {@code controller.setToolParam(...)}（key 即 config 字段名），和生成链路
 * （toolParams → 工具 config builder）完全一致 —— 面板只负责长什么样。
 */
public class GodzillaSessionToolPanel extends AbstractToolPanel {
    private static final String PASS = "pass";
    private static final String KEY = "key";
    private static final String HEADER_NAME = "headerName";
    private static final String HEADER_VALUE = "headerValue";
    private static final String SESSION_KEY = "sessionKey";

    private final JTextField passField = new JTextField();
    private final JTextField keyField = new JTextField();
    private final JTextField headerNameField = new JTextField();
    private final JTextField headerValueField = new JTextField();
    private final JTextField sessionKeyField = new JTextField();

    public GodzillaSessionToolPanel(ToolPanelContext context) {
        super(context.getController(), context.getRefreshAll());
        for (JTextField field : new JTextField[]{passField, keyField, headerValueField, sessionKeyField}) {
            field.putClientProperty("JTextField.placeholderText", "留空则随机生成");
        }
        add(labeled("密码", passField), "growx");
        add(labeled("密钥", keyField), "growx");
        add(labeled("请求头名", headerNameField), "growx");
        add(labeled("请求头值", headerValueField), "growx");
        add(labeled("会话 Key", sessionKeyField), "growx, wrap");

        bindText(passField, v -> controller.setToolParam(PASS, v));
        bindText(keyField, v -> controller.setToolParam(KEY, v));
        bindText(headerNameField, v -> controller.setToolParam(HEADER_NAME, v));
        bindText(headerValueField, v -> controller.setToolParam(HEADER_VALUE, v));
        bindText(sessionKeyField, v -> controller.setToolParam(SESSION_KEY, v));
    }

    @Override
    public void refreshFromController() {
        super.refreshFromController();
        updating = true;
        try {
            MemShellFormState s = controller.getState();
            passField.setText(s.getToolParam(PASS));
            keyField.setText(s.getToolParam(KEY));
            headerNameField.setText(s.getToolParam(HEADER_NAME));
            headerValueField.setText(s.getToolParam(HEADER_VALUE));
            sessionKeyField.setText(s.getToolParam(SESSION_KEY));
        } finally {
            updating = false;
        }
    }
}
