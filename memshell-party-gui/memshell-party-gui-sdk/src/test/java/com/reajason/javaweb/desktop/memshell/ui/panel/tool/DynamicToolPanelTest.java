package com.reajason.javaweb.desktop.memshell.ui.panel.tool;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.desktop.memshell.controller.MemShellFormController;
import com.reajason.javaweb.desktop.memshell.service.ConfigCatalogService;
import com.reajason.javaweb.desktop.memshell.validation.MemShellValidator;
import com.reajason.javaweb.memshell.MemShellRegistry;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import java.awt.Component;
import java.awt.Container;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * 动态参数面板的字段名与占位提示：{@code @ConfigField} 写了就用注解上的，没写才回落内置参数表
 * —— 插件工具（Dandelion 这类）没在内置表里登记过，中文名与语义提示只能靠注解带出来。
 */
class DynamicToolPanelTest {

    private static final String PLUGIN_TOOL = "TestLabelledTool";

    private final MemShellFormController controller =
            new MemShellFormController(new ConfigCatalogService(), new MemShellValidator());
    private final Runnable refreshAll = new Runnable() {
        @Override
        public void run() {
        }
    };

    @Test
    void annotationLabelAndPlaceholderWin() {
        registerPluginTool();
        Map<String, String> fields = textFieldsOf(new DynamicToolPanel(PLUGIN_TOOL, controller, refreshAll));
        assertEquals("留空则随机生成", fields.get("密码"));
        // 只写了 label 没写 placeholder：提示回落通用文案，而不是把参数名当标签
        assertEquals("留空使用默认值", fields.get("自定义参数"));
    }

    @Test
    void builtInParamsKeepTheirRegisteredLabels() {
        Map<String, String> fields = textFieldsOf(new DynamicToolPanel(ShellTool.Godzilla, controller, refreshAll));
        assertEquals("留空则随机生成", fields.get("密码"));
        assertEquals("留空则随机生成", fields.get("密钥"));
    }

    /**
     * 面板上的「标签 → 占位提示」：只取参数行（公共行没有提示、枚举行不是文本框）。
     */
    private static Map<String, String> textFieldsOf(Container panel) {
        Map<String, String> byLabel = new LinkedHashMap<String, String>();
        for (Component row : panel.getComponents()) {
            if (!(row instanceof JPanel)) {
                continue;
            }
            String label = null;
            JTextField field = null;
            for (Component cell : ((JPanel) row).getComponents()) {
                if (cell instanceof JLabel && label == null && !((JLabel) cell).getText().isEmpty()) {
                    label = ((JLabel) cell).getText();
                } else if (cell instanceof JTextField) {
                    field = (JTextField) cell;
                }
            }
            if (label != null && field != null) {
                byLabel.put(label, (String) field.getClientProperty("JTextField.placeholderText"));
            }
        }
        return byLabel;
    }

    /**
     * 造一个 core 里注册过的插件工具：面板要能从 registry 里解析出它的参数（= 已标注的字段）。
     */
    private static void registerPluginTool() {
        MemShellRegistry.getInstance().registerTool(PLUGIN_TOOL, new ShellToolProvider() {
            @Override
            public ToolMapping getToolMapping() {
                return ToolMapping.builder().build();
            }

            @Override
            public Class<? extends ShellToolConfig> getConfigClass() {
                return LabelledConfig.class;
            }

            @Override
            public Class<? extends ShellGenerator> getGeneratorClass() {
                return null;
            }
        });
    }

    @SuppressWarnings("unused")
    private static class LabelledConfig extends ShellToolConfig {
        @ConfigField(label = "密码", placeholder = "留空则随机生成")
        private String pass;

        @ConfigField(label = "自定义参数")
        private String custom;
    }
}
