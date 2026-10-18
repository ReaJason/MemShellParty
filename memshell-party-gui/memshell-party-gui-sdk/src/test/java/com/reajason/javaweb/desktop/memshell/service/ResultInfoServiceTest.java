package com.reajason.javaweb.desktop.memshell.service;

import com.reajason.javaweb.desktop.memshell.model.InfoRow;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 结果区工具参数行：行集由 {@code @ConfigField} 目录驱动（本模块编译期不认识任何内置工具类），
 * 但行名、行序、可见性必须与 web basic-info.tsx 和表单一致 —— 这三处是同一份展示口径。
 */
class ResultInfoServiceTest {

    private final MemShellGenerator generator = new MemShellGenerator();

    /**
     * 行序对齐 web：Godzilla 是 密码 / 密钥 / 派生加密器 / 请求头。
     */
    @Test
    void godzillaRowOrderMatchesWeb() {
        List<InfoRow> rows = rowsOf("Godzilla", "Tomcat", "Listener", null);
        assertEquals(Arrays.asList("密码", "密钥", "加密器", "请求头"), names(rows));
        assertFalse(rows.get(0).getValue().isEmpty(), "随机密码应当有值");
        assertFalse(rows.get(1).getValue().isEmpty(), "随机密钥应当有值");
        assertTrue(rows.get(2).getValue().startsWith("JAVA_"), rows.get(2).getValue());
    }

    /**
     * 请求头名/值合成一行「请求头」展示，而不是拆成两行；缺了 headerValue 也不该出现空悬行。
     */
    @Test
    void headerNameAndValueCollapseIntoOneRow() {
        List<InfoRow> rows = rowsOf("Suo5", "Tomcat", "Filter", null);
        assertEquals(Arrays.asList("请求头"), names(rows));
        assertTrue(rows.get(0).getValue().contains(": "), rows.get(0).getValue());
    }

    /**
     * Command 的参数名在 WebSocket 下不显示（走请求头传参），加密器/实现类恒显示，
     * 命令模板没填就不占一行 —— 与 {@code ToolParamVisibility} 和表单同一套规则。
     */
    @Test
    void commandRowsFollowParamVisibility() {
        assertEquals(Arrays.asList("参数名", "加密器", "实现类"),
                names(rowsOf("Command", "Tomcat", "Servlet", "/cmd")));
        assertEquals(Arrays.asList("加密器", "实现类"),
                names(rowsOf("Command", "Tomcat", "WebSocket", null)));
    }

    /**
     * Proxy 的请求头只在 BypassNginx 的 WebSocket 回落里当"暗号"，其余挂载类型下整行隐藏。
     */
    @Test
    void proxyHeaderRowOnlyShowsForBypassNginxWebSocket() {
        assertTrue(rowsOf("Proxy", "Tomcat", "WebSocket", null).isEmpty());
        assertEquals(Arrays.asList("请求头"),
                names(rowsOf("Proxy", "Tomcat", "BypassNginxWebSocket", null)));
    }

    /**
     * 内置工具的中文名来自共用参数表（{@code ToolParamLabels}）：标签漂移会让结果区与表单对不上。
     */
    @Test
    void builtInToolRowsUseTheSharedChineseLabels() {
        assertEquals(Arrays.asList("密码", "请求头"), names(rowsOf("Behinder", "Tomcat", "Filter", null)));
        assertEquals(Arrays.asList("密码", "请求头"), names(rowsOf("AntSword", "Tomcat", "Filter", null)));
        assertEquals(Arrays.asList("请求头"), names(rowsOf("NeoreGeorg", "Tomcat", "Filter", null)));
    }

    /**
     * Custom 的 base64 长值行：名字与表单一致（{@code shellClassBase64} 在共用参数表里登记过）。
     */
    @Test
    void customToolRowShowsTheBase64Payload() {
        MemShellResult shell = generator.generate(
                ShellConfig.builder().server("Tomcat").shellTool("Godzilla").shellType("Listener").build(),
                InjectorConfig.builder().build(), new HashMap<String, String>());
        Map<String, String> params = new HashMap<String, String>();
        params.put("shellClassBase64", shell.getShellBytesBase64Str());

        MemShellResult custom = generator.generate(
                ShellConfig.builder().server("Tomcat").shellTool("Custom").shellType("Listener").build(),
                InjectorConfig.builder().build(), params);
        List<InfoRow> rows = ResultInfoService.describeTool(custom.getShellConfig(), custom.getShellToolConfig());
        assertEquals(Arrays.asList("自定义类(Base64)"), names(rows));
        assertEquals(shell.getShellBytesBase64Str(), rows.get(0).getValue());
    }

    /**
     * 插件工具（未注册进注册表的 config 类）：只出自己标注的字段，
     * 基类的生成配置（由生成器填充、固定类名行已展示）不重复出现。
     */
    @Test
    void pluginToolRowsComeFromItsOwnAnnotations() {
        PluginConfig config = new PluginConfig();
        List<InfoRow> rows = ResultInfoService.describeTool(null, config);
        assertEquals(Arrays.asList("会话密钥", "custom"), names(rows));
    }

    /**
     * 工具配置缺失（如生成失败后的空结果）时不出任何行，而不是抛异常。
     */
    @Test
    void missingToolConfigProducesNoRows() {
        assertTrue(ResultInfoService.describeTool(null, null).isEmpty());
    }

    private List<InfoRow> rowsOf(String tool, String server, String shellType, String urlPattern) {
        MemShellResult result = generator.generate(
                ShellConfig.builder().server(server).shellTool(tool).shellType(shellType).build(),
                InjectorConfig.builder().urlPattern(urlPattern).build(), new HashMap<String, String>());
        return ResultInfoService.describeTool(result.getShellConfig(), result.getShellToolConfig());
    }

    private static List<String> names(List<InfoRow> rows) {
        List<String> names = new ArrayList<String>();
        for (InfoRow row : rows) {
            names.add(row.getName());
        }
        return names;
    }

    /**
     * 插件工具 config：{@code sessionKey} 写了 label 显示中文，{@code custom} 没写回落字段名。
     */
    private static final class PluginConfig extends com.reajason.javaweb.memshell.config.ShellToolConfig {
        @com.reajason.javaweb.memshell.config.ConfigField(label = "会话密钥")
        private String sessionKey = "sessionCore";

        @com.reajason.javaweb.memshell.config.ConfigField
        private String custom = "v";

        public String getSessionKey() {
            return sessionKey;
        }

        public String getCustom() {
            return custom;
        }
    }
}
