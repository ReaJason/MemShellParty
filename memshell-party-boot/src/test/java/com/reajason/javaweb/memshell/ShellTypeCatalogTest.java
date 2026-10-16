package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 支持矩阵的按轴查询：每一轴都要与注册表逐层问出来的结果一致，
 * 未知组合返回空表而不是 null，矩阵本身不可修改。
 *
 * @author ReaJason
 * @since 3.0.0
 */
class ShellTypeCatalogTest {

    private final MemShellRegistry registry = MemShellRegistry.getInstance();
    private final MemShellGenerator.ShellTypeCatalog catalog = new MemShellGenerator().getShellTypeCatalog();

    /**
     * 直接问注册表的期望值：该服务端「至少有一个可注入类型」的工具，顺序与 {@link AbstractServer} 一致。
     */
    private List<String> expectedShellTools(String serverName) {
        AbstractServer server = registry.getServer(serverName);
        List<String> tools = new ArrayList<>();
        for (String shellTool : server.getSupportedShellTools()) {
            if (!server.getSupportedShellTypes(shellTool).isEmpty()) {
                tools.add(shellTool);
            }
        }
        return tools;
    }

    @Test
    void serversMatchRegistry() {
        assertEquals(registry.getSupportedServers(), catalog.getServers());
    }

    @Test
    void shellToolsMatchRegistryPerServer() {
        for (String serverName : registry.getSupportedServers()) {
            assertEquals(expectedShellTools(serverName), catalog.getShellTools(serverName), serverName);
        }
    }

    @Test
    void shellTypesMatchServerInjectorMapping() {
        for (String serverName : registry.getSupportedServers()) {
            AbstractServer server = registry.getServer(serverName);
            for (String shellTool : catalog.getShellTools(serverName)) {
                assertEquals(new ArrayList<>(server.getSupportedShellTypes(shellTool)),
                        catalog.getShellTypes(serverName, shellTool), serverName + " / " + shellTool);
            }
        }
    }

    /**
     * 反查：某工具的支持服务端，必须与「逐个服务端问该工具」得到的一致。
     */
    @Test
    void serversSupportingAgreesWithPerServerLookup() {
        for (String shellTool : registry.getSupportedTools()) {
            List<String> expected = new ArrayList<>();
            for (String serverName : catalog.getServers()) {
                if (catalog.getShellTools(serverName).contains(shellTool)) {
                    expected.add(serverName);
                }
            }
            assertEquals(expected, catalog.getServersSupporting(shellTool), shellTool);
        }
    }

    /**
     * XxlJob 只注入 NETTY_HANDLER，只有 Command/Godzilla 有对应模板 —— 反查也得跟着这个事实。
     */
    @Test
    void xxlJobOnlyAdvertisesTemplatedTools() {
        assertEquals(Arrays.asList(ShellTool.Godzilla, ShellTool.Command), catalog.getShellTools(Server.XXLJOB));
        assertTrue(catalog.getServersSupporting(ShellTool.Command).contains(Server.XXLJOB));
        assertFalse(catalog.getServersSupporting(ShellTool.Suo5).contains(Server.XXLJOB));
    }

    @Test
    void unknownAxisValuesReturnEmptyLists() {
        assertTrue(catalog.getShellTools("NoSuchServer").isEmpty());
        assertTrue(catalog.getShellTypes("NoSuchServer", ShellTool.Godzilla).isEmpty());
        assertTrue(catalog.getShellTypes("Tomcat", "NoSuchTool").isEmpty());
        assertTrue(catalog.getServersSupporting("NoSuchTool").isEmpty());
        // 界面上工具/服务端还没选时就是 null，不能炸
        assertTrue(catalog.getShellTools(null).isEmpty());
        assertTrue(catalog.getShellTypes(null, null).isEmpty());
        assertTrue(catalog.getServersSupporting(null).isEmpty());
    }

    @Test
    void queriesHandOutCopiesAndTheMatrixIsUnmodifiable() {
        List<String> servers = catalog.getServers();
        servers.clear();
        assertFalse(catalog.getServers().isEmpty(), "取到的列表应当是副本，改它不影响目录");

        assertThrows(UnsupportedOperationException.class, () -> catalog.asMap().clear());
    }
}
