package com.reajason.javaweb.desktop.memshell.ui.panel;

import com.reajason.javaweb.desktop.memshell.model.DesktopMemShellGenerateResult;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.ConfigField;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.Packers;
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

    /**
     * 类名是后续连接/排查时要认全的标识，即使超过截断长度也要完整展示（不再出现 ...）。
     */
    @Test
    void classNameRowsAreShownInFull() {
        String shellClassName = "com.example.memshell.generated.very.long.package.name.thats.exceeds.display.limit.Shell";
        String injectorClassName = "com.example.injector.generated.very.long.package.name.thats.exceeds.display.limit.Injector";
        assertTrue(shellClassName.length() > 64, "用例前提：类名超过截断长度");

        BasicInfoPanel panel = new BasicInfoPanel();
        panel.setResult(resultWithClassNames(shellClassName, injectorClassName));

        List<String> values = valueTexts(panel);
        assertTrue(values.contains(shellClassName + " (5002 bytes)"), values.toString());
        assertTrue(values.contains(injectorClassName + " (11467 bytes)"), values.toString());
        assertFalse(values.contains(shellClassName + " (5002 bytes)..."), values.toString());
    }

    private static DesktopMemShellGenerateResult resultWithPluginConfig() {
        return resultWithClassNames("com.example.RandomShell", "com.example.RandomInjector");
    }

    private static DesktopMemShellGenerateResult resultWithClassNames(String shellClassName, String injectorClassName) {
        PluginToolConfig toolConfig = new PluginToolConfig();
        // 生成期由 MemShellGenerator 填充基类字段（模板类名来自工具映射，类名随机生成）
        toolConfig.setShellTemplateClassName("com.example.template.GodzillaSessionListener");
        toolConfig.setShellClassName(shellClassName);
        MemShellResult result = MemShellResult.builder()
                .shellClassName(shellClassName)
                .injectorClassName(injectorClassName)
                .shellSize(5002)
                .injectorSize(11467)
                .shellToolConfig(toolConfig)
                .build();
        return new DesktopMemShellGenerateResult(result, Packers.DefaultBase64, "AAAA");
    }

    /**
     * 收集全部行标签文案（形如 {@code key:}）；值标签不含冒号结尾，天然区分开。
     */
    private static List<String> rowKeys(Container root) {
        List<String> keys = new ArrayList<String>();
        collect(root, keys);
        return keys;
    }

    /**
     * 收集全部值标签文案（行标签以冒号结尾，值标签不会）。
     */
    private static List<String> valueTexts(Container root) {
        List<String> values = new ArrayList<String>();
        collectValues(root, values);
        return values;
    }

    private static void collectValues(Container root, List<String> values) {
        for (Component child : root.getComponents()) {
            if (child instanceof JLabel) {
                String text = ((JLabel) child).getText();
                if (text != null && !text.endsWith(":")) {
                    values.add(text);
                }
            }
            if (child instanceof Container) {
                collectValues((Container) child, values);
            }
        }
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
