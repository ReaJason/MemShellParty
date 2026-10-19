package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies that SPI discovery reproduces the server/tool matrix the deleted
 * ServerFactory used to hardcode.
 *
 * @author ReaJason
 * @since 2025/8/25
 */
class MemShellRegistryTest {

    private final MemShellRegistry registry = MemShellRegistry.getInstance();

    @Test
    void testSupportedServers() {
        List<String> supportedServers = registry.getSupportedServers();
        assertTrue(supportedServers.size() >= 19, "expected all built-in servers, got " + supportedServers);
        assertTrue(supportedServers.containsAll(Arrays.asList(
                Server.Tomcat, Server.Jetty, Server.Jetty5, Server.Undertow, Server.SpringWebMvc,
                Server.SpringWebFlux, Server.Dubbo, Server.XXLJOB, Server.BES, Server.TongWeb)),
                "missing servers in " + supportedServers);
    }

    @Test
    void testSupportedTools() {
        assertEquals(new TreeSet<>(Arrays.asList(
                        ShellTool.Godzilla, ShellTool.GodzillaSession, ShellTool.Behinder, ShellTool.AntSword,
                        ShellTool.Command, ShellTool.Suo5, ShellTool.NeoreGeorg, ShellTool.Proxy, ShellTool.Custom)),
                new TreeSet<>(registry.getSupportedTools()));
    }

    /**
     * XxlJob only injects NETTY_HANDLER, and only Command/Godzilla template it — the mapping
     * must stay filtered by the server's injector mapping instead of exposing every tool.
     */
    @Test
    void testXxlJobTools() {
        AbstractServer server = registry.getServer(Server.XXLJOB);
        assertNotNull(server);
        Set<String> supportedShellTools = server.getSupportedShellTools();
        assertEquals(2, supportedShellTools.size(), "got " + supportedShellTools);
        assertTrue(supportedShellTools.contains(ShellTool.Command));
        assertTrue(supportedShellTools.contains(ShellTool.Godzilla));
    }

    /**
     * 工具列表按 {@code @ShellToolMeta(order)}（即 ShellTool 常量声明顺序）排列，UI 下拉框
     * 不能随哈希序漂移。
     */
    @Test
    void testToolOrder() {
        AbstractServer server = registry.getServer(Server.Tomcat);
        assertNotNull(server);
        assertEquals(Arrays.asList(
                        ShellTool.Godzilla, ShellTool.GodzillaSession, ShellTool.Behinder, ShellTool.Command,
                        ShellTool.Suo5, ShellTool.AntSword, ShellTool.NeoreGeorg, ShellTool.Proxy),
                new ArrayList<>(server.getSupportedShellTools()));
    }

    /**
     * 生成配置自身的字段（shellClassName/shellTemplateClassName）不属于工具参数，不应作为
     * 可编辑项暴露给 REST/MCP/GUI。
     */
    @Test
    void testDescribeParamsHidesGenerationConfig() {
        for (String tool : registry.getSupportedTools()) {
            for (ToolConfigFactory.ConfigParam param : ToolConfigFactory.describeParams(tool)) {
                assertFalse("shellClassName".equals(param.getName()), tool + " exposes shellClassName");
                assertFalse("shellTemplateClassName".equals(param.getName()), tool + " exposes shellTemplateClassName");
            }
        }
    }
}
