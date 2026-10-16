package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import org.junit.jupiter.api.Test;

import javax.swing.JLabel;
import java.awt.Component;
import java.awt.Container;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 插件工具（SPI 新增的 shelltool）基本信息兜底行：只展示工具自己的参数，
 * 不重复基类里由生成器填充、下方固定行已展示的类名字段。
 */
class BasicInfoPanelTest {

    @Test
    void pluginToolRowsDoNotRepeatTheGeneratedClassNames() {
        BasicInfoPanel panel = new BasicInfoPanel();
        panel.setResult(resultWithPluginConfig());

        List<String> keys = rowKeys(panel);
        // 基类的生成配置字段属于固定行（注入器类名 / 内存马类名），兜底行里不再出现
        assertFalse(keys.contains("shellClassName:"), keys.toString());
        assertFalse(keys.contains("shellTemplateClassName:"), keys.toString());
        // 工具自己的参数照常展示，名字取 @ConfigField 的 label（表单里显示什么，这里就显示什么）
        assertFalse(keys.contains("sessionKey:"), keys.toString());
        assertTrue(keys.contains("会话密钥:"), keys.toString());
        // 固定行还在
        assertTrue(keys.contains("内存马类名:"), keys.toString());
        assertTrue(keys.contains("注入器类名:"), keys.toString());
    }

    private static DesktopMemShellGenerateResult resultWithPluginConfig() {
        PluginToolConfig toolConfig = new PluginToolConfig();
        // 生成期由 MemShellGenerator 填充基类字段（模板类名来自工具映射，类名随机生成）
        toolConfig.setShellTemplateClassName("com.example.template.GodzillaSessionListener");
        toolConfig.setShellClassName("com.example.RandomShell");
        MemShellResult result = MemShellResult.builder()
                .shellClassName("com.example.RandomShell")
                .injectorClassName("com.example.RandomInjector")
                .shellSize(5002)
                .injectorSize(11467)
                .shellToolConfig(toolConfig)
                .build();
        return new DesktopMemShellGenerateResult(result, "DefaultBase64", "AAAA");
    }

    /**
     * 收集全部行标签文案（形如 {@code key:}）；值标签不含冒号结尾，天然区分开。
     */
    private static List<String> rowKeys(Container root) {
        List<String> keys = new ArrayList<String>();
        collect(root, keys);
        return keys;
    }

    private static void collect(Container root, List<String> keys) {
        for (Component child : root.getComponents()) {
            if (child instanceof JLabel) {
                String text = ((JLabel) child).getText();
                if (text != null && text.endsWith(":")) {
                    keys.add(text);
                }
            }
            if (child instanceof Container) {
                collect((Container) child, keys);
            }
        }
    }

    /**
     * 插件工具配置：基类两个类名字段由生成器填充，自己只多一个 sessionKey
     * （带 {@code @ConfigField} 的 label，结果区据此显示中文名）。
     */
    private static final class PluginToolConfig extends ShellToolConfig {
        @ConfigField(label = "会话密钥")
        private String sessionKey = "sessionCore";

        public String getSessionKey() {
            return sessionKey;
        }

        public void setSessionKey(String sessionKey) {
            this.sessionKey = sessionKey;
        }
    }
}
