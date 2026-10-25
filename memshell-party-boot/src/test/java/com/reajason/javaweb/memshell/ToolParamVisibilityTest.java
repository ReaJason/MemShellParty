package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.server.AbstractServer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 参数适用性规则：两端表单靠它决定某个字段要不要出现，判错的后果是"填了不生效"或"该填的看不到"。
 *
 * @author ReaJason
 * @since 3.0.0
 */
class ToolParamVisibilityTest {

    @Test
    void commandParamNameHidesForWebSocketAndDubbo() {
        assertTrue(visible(ShellTool.Command, "paramName", "Tomcat", "Servlet"));
        assertFalse(visible(ShellTool.Command, "paramName", "Tomcat", "WebSocket"));
        assertFalse(visible(ShellTool.Command, "paramName", "Tomcat", "JakartaWebSocket"));
        assertFalse(visible(ShellTool.Command, "paramName", "Dubbo", "Servlet"));
    }

    /**
     * 其余工具（含插件工具）没有声明即全可见 —— 兜底方向必须偏"显示"，否则插件参数会凭空消失。
     */
    @Test
    void otherToolsAndParamsStayVisible() {
        assertTrue(visible(ShellTool.Godzilla, "headerName", "Tomcat", "Listener"));
        assertTrue(visible(ShellTool.NeoreGeorg, "headerName", "Tomcat", "Servlet"));
        assertTrue(visible(ShellTool.Custom, "shellClassBase64", "Tomcat", "Filter"));
        assertTrue(visible("MyPluginTool", "anyParam", "Tomcat", "Filter"));

        // Command 的加密器/模板与挂载类型无关
        assertTrue(visible(ShellTool.Command, "encryptor", "Tomcat", "WebSocket"));
        assertTrue(visible(ShellTool.Command, "template", "Dubbo", "Servlet"));
    }

    /**
     * 漂移保险丝：规则里写到的参数名必须真的是那个工具的字段，否则规则永远不会命中。
     */
    @Test
    void rulesReferToRealParams() {
        assertTrue(paramNamesOf(ShellTool.Command).contains("paramName"),
                "Command 应当有 paramName，否则规则形同虚设");
    }

    /**
     * 漂移保险丝：规则里比较的挂载类型必须是注册中心真的会下发的名字，
     * 否则该分支永远不成立。
     */
    @Test
    void rulesReferToRealShellTypes() {
        Set<String> known = new TreeSet<>();
        MemShellGenerator memShellGenerator = new MemShellGenerator();
        for (String serverName : memShellGenerator.getSupportedServers()) {
            AbstractServer server = memShellGenerator.getServer(serverName);
            for (String tool : memShellGenerator.getSupportedTools()) {
                known.addAll(server.getSupportedShellTypes(tool));
            }
        }
        for (String shellType : new String[]{ShellType.WEBSOCKET}) {
            assertTrue(known.contains(shellType),
                    "规则里用到的挂载类型 " + shellType + " 并不存在，可用：" + known);
        }
    }

    private static List<String> paramNamesOf(String tool) {
        List<String> names = new ArrayList<>();
        for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(tool)) {
            names.add(param.getName());
        }
        return names;
    }

    private static boolean visible(String tool, String param, String server, String shellType) {
        return ToolParamVisibility.isVisible(tool, param, server, shellType);
    }
}
