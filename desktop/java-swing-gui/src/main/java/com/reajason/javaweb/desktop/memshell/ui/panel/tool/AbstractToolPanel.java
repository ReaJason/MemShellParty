package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.MemShellFormState;
import com.reajason.javaweb.desktop.memshell.util.SwingUiUtil;
import net.miginfocom.swing.MigLayout;

import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.util.List;
import java.util.function.Consumer;

/**
 * 工具面板公共部分：挂载类型下拉 + 请求路径（不可用时置灰而非隐藏，避免布局跳动）。
 * 内存马类名与注入器类名在核心配置面板（留空即随机生成），不在工具卡内。
 */
public abstract class AbstractToolPanel extends JPanel implements RefreshableToolPanel {
    protected final MemShellFormController controller;
    protected final Runnable refreshAll;
    protected boolean updating;

    protected final JComboBox<String> shellTypeCombo = new JComboBox<String>();
    protected final JTextField urlPatternField = new JTextField();
    private final JLabel urlPatternLabel;

    protected AbstractToolPanel(MemShellFormController controller, Runnable refreshAll) {
        this.controller = controller;
        this.refreshAll = refreshAll;
        setLayout(new MigLayout("insets 6, fillx, gapx 8, gapy 3, wrap 2", "[sg col,grow,fill][sg col,grow,fill]", "[]"));

        add(labeled("内存马挂载类型", shellTypeCombo), "growx");
        JPanel urlPatternRow = labeled("请求路径", urlPatternField);
        urlPatternLabel = (JLabel) urlPatternRow.getComponent(0);
        add(urlPatternRow, "growx");

        shellTypeCombo.addActionListener(e -> {
            if (updating) return;
            SwingUiUtil.clearFieldError(shellTypeCombo);
            Object item = shellTypeCombo.getSelectedItem();
            if (item != null) {
                controller.setShellType(String.valueOf(item));
                refreshAll.run();
            }
        });
        bindText(urlPatternField, controller::setUrlPattern);
    }

    /**
     * inline 校验：挂载类型 / 请求路径错误标到对应行（红描边 + 行内红字）。
     */
    public void applyValidationErrors(java.util.Map<String, String> errors) {
        String shellTypeError = errors.get("shellType");
        if (shellTypeError != null) {
            SwingUiUtil.setFieldError(shellTypeCombo, shellTypeError);
        }
        String urlPatternError = errors.get("urlPattern");
        if (urlPatternError != null) {
            SwingUiUtil.setFieldError(urlPatternField, urlPatternError);
        }
    }

    /**
     * 校验失败时焦点跳转目标；字段不属于本面板返回 null。
     */
    public JComponent validationFocusTarget(String field) {
        if ("shellType".equals(field)) return shellTypeCombo;
        if ("urlPattern".equals(field)) return urlPatternField;
        return null;
    }

    /**
     * 公共部分状态回填：重建挂载类型下拉、请求路径文本与可用性。
     */
    protected void applyCommonState(MemShellFormState s) {
        setComboItems(shellTypeCombo, controller.getShellTypesForCurrentTool(), s.getShellType());
        urlPatternField.setText(s.getUrlPattern());
        // 请求路径不适用时置灰而非隐藏：隐藏会导致行高塌陷、布局跳动
        boolean urlPatternEnabled = controller.isUrlPatternVisible();
        urlPatternField.setEnabled(urlPatternEnabled);
        urlPatternLabel.setEnabled(urlPatternEnabled);
    }

    @Override
    public void refreshFromController() {
        updating = true;
        try {
            applyCommonState(controller.getState());
        } finally {
            updating = false;
        }
    }

    protected JPanel labeled(String label, JComponent component) {
        return SwingUiUtil.labeled(label, component);
    }

    protected void setComboItems(JComboBox<String> combo, List<String> items, String selected) {
        combo.removeAllItems();
        for (String item : items) {
            combo.addItem(item);
        }
        if (selected != null) {
            combo.setSelectedItem(selected);
        }
    }

    protected void bindText(JTextField field, Consumer<String> setter) {
        field.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                changed();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                changed();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                changed();
            }

            private void changed() {
                if (updating) return;
                SwingUiUtil.clearFieldError(field);
                setter.accept(field.getText());
            }
        });
    }
}
