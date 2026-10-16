package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.model.ToolParamLabels;
import com.reajason.javaweb.memshell.ToolConfigFactory;
import com.reajason.javaweb.memshell.config.ConfigField;
import net.miginfocom.swing.MigLayout;

import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * 工具参数面板：按 {@link ToolConfigFactory#describeParams} 读出的 {@code @ConfigField} 参数动态生成表单 ——
 * String → 文本框，枚举 → 下拉框（选中项即工具默认值），字段声明顺序就是表单顺序，
 * BASIC 直接铺开、ADVANCED 收进「高级配置」。内置工具与插件工具共用这一份实现，
 * SPI 新增的 ShellTool 不用改任何界面代码；只有 Custom（base64 ⇄ .class）另有专用面板。
 * <p>
 * 参数写进 {@code state.toolParams}（key 即字段名），空值跳过让 builder 默认值生效；
 * 当前服务端 / 挂载类型下用不到的参数按 {@code ToolParamVisibility} 整行隐藏。
 */
public class DynamicToolPanel extends AbstractToolPanel {

    /**
     * 随机默认值（pass/key…）当占位提示会让人误以为是已填的值，所以只对确定语义的参数给提示，
     * 其余统一说「留空使用默认值」；注解上写了 {@code placeholder} 的以注解为准。
     */
    private static final Map<String, String> PLACEHOLDERS = placeholders();

    private final Map<String, JComponent> fields = new LinkedHashMap<String, JComponent>();
    private final Map<String, JComponent> rows = new LinkedHashMap<String, JComponent>();

    public DynamicToolPanel(String toolName, MemShellFormController controller, Runnable refreshAll) {
        super(controller, refreshAll);

        JPanel advancedPanel = new JPanel(new MigLayout(
                "insets 4 8 0 8, fillx, hidemode 3, gapx 8, gapy 3, wrap 2",
                "[sg col,grow,fill][sg col,grow,fill]", "[]"));
        JCheckBox advancedToggle = new JCheckBox("高级配置");
        boolean hasAdvanced = false;

        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(toolName)) {
            JComponent field = createField(toolName, param);
            JComponent row = labeled(ToolParamLabels.of(param.getName(), param.getLabel()), field);
            fields.put(param.getName(), field);
            rows.put(param.getName(), row);
            if (ConfigField.Group.ADVANCED.equals(param.getGroup())) {
                hasAdvanced = true;
                advancedPanel.add(row, "growx");
            } else {
                add(row, "growx");
            }
        }

        if (hasAdvanced) {
            advancedPanel.setVisible(false);
            add(advancedToggle, "span 2, gapy 2 0, wrap");
            add(advancedPanel, "span 2, growx, wrap");
            advancedToggle.addActionListener(e -> advancedPanel.setVisible(advancedToggle.isSelected()));
        }
    }

    private JComponent createField(final String toolName, final ToolConfigFactory.ConfigParam param) {
        if ("enum".equals(param.getType())) {
            final JComboBox<String> combo = new JComboBox<String>();
            for (String option : param.getOptions()) {
                combo.addItem(option);
            }
            // 未显式指定时显示工具默认值（留空发出去同样落到这个默认值），下拉里因此没有空选项
            String defaultValue = ToolConfigFactory.defaultParamValue(toolName, param.getName());
            if (defaultValue != null) {
                combo.setSelectedItem(defaultValue);
            }
            combo.addActionListener(e -> {
                if (updating) return;
                Object item = combo.getSelectedItem();
                controller.setToolParam(param.getName(), item == null ? "" : String.valueOf(item));
            });
            return combo;
        }
        JTextField field = new JTextField();
        field.putClientProperty("JTextField.placeholderText", param.getPlaceholder().isEmpty()
                ? PLACEHOLDERS.getOrDefault(param.getName(), "留空使用默认值")
                : param.getPlaceholder());
        bindText(field, v -> controller.setToolParam(param.getName(), v));
        return field;
    }

    @Override
    public void refreshFromController() {
        updating = true;
        try {
            applyCommonState(controller.getState());
            for (Map.Entry<String, JComponent> entry : fields.entrySet()) {
                String value = controller.getState().getToolParam(entry.getKey());
                JComponent field = entry.getValue();
                if (field instanceof JTextField) {
                    ((JTextField) field).setText(value);
                } else if (field instanceof JComboBox) {
                    // 留空说明用工具默认值，下拉里保持默认项选中（不要把一个不存在的空选项塞进去）
                    if (!value.isEmpty()) {
                        ((JComboBox<?>) field).setSelectedItem(value);
                    }
                }
            }
        } finally {
            updating = false;
        }
        for (Map.Entry<String, JComponent> entry : rows.entrySet()) {
            entry.getValue().setVisible(controller.isToolParamVisible(entry.getKey()));
        }
    }

    private static Map<String, String> placeholders() {
        Map<String, String> placeholders = new LinkedHashMap<String, String>();
        placeholders.put("pass", "留空则随机生成");
        placeholders.put("key", "留空则随机生成");
        placeholders.put("paramName", "留空则随机生成");
        placeholders.put("headerValue", "留空则随机生成");
        placeholders.put("template", "留空则直接执行命令");
        return Collections.unmodifiableMap(placeholders);
    }
}
