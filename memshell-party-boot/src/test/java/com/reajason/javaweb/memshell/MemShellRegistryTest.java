package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.utils.tuple.Pair;
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
     * Resin 3/4 都不走容器 WebSocket API：RawWebSocket 模板与 Tomcat 共用，注入器换成
     * 会先 defineClass helper 的 ResinRawWsInjector。
     */
    @Test
    void testResinRawWebSocketUsesHelperInjector() {
        AbstractServer resin = registry.getServer(Server.Resin);
        assertNotNull(resin);
        assertTrue(resin.getSupportedShellTypes(ShellTool.Command).contains(ShellType.RAW_WEBSOCKET));
        assertTrue(resin.getSupportedShellTypes(ShellTool.Godzilla).contains(ShellType.RAW_WEBSOCKET));
        assertTrue(resin.getSupportedShellTypes(ShellTool.Proxy).contains(ShellType.RAW_WEBSOCKET));
        assertFalse(resin.getSupportedShellTypes(ShellTool.Command).contains(ShellType.WEBSOCKET));

        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                resin.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaRawWebSocket",
                resin.getShellInjectorPair(ShellTool.Godzilla, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyRawWebSocket",
                resin.getShellInjectorPair(ShellTool.Proxy, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.injector.resin.ResinRawWsInjector",
                resin.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getRight());

        AbstractServer tomcat = registry.getServer(Server.Tomcat);
        assertNotNull(tomcat);
        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandWebSocket",
                shellTemplate(tomcat, ShellTool.Command));
        assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaWebSocket",
                shellTemplate(tomcat, ShellTool.Godzilla));
    }

    /**
     * RawWebSocket 的握手与帧协议由 Tomcat 专属 helper 接管，模板本身与容器无关；
     * 注入器必须换成负责先 defineClass helper 的 TomcatRawWsInjector。
     */
    @Test
    void testTomcatRawWebSocketUsesHelperInjector() {
        AbstractServer tomcat = registry.getServer(Server.Tomcat);
        assertNotNull(tomcat);
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Command).contains(ShellType.RAW_WEBSOCKET));
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Godzilla).contains(ShellType.RAW_WEBSOCKET));
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Proxy).contains(ShellType.RAW_WEBSOCKET));
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Command).contains(ShellType.JAKARTA_RAW_WEBSOCKET));
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Godzilla).contains(ShellType.JAKARTA_RAW_WEBSOCKET));
        assertTrue(tomcat.getSupportedShellTypes(ShellTool.Proxy).contains(ShellType.JAKARTA_RAW_WEBSOCKET));

        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                tomcat.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaRawWebSocket",
                tomcat.getShellInjectorPair(ShellTool.Godzilla, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyRawWebSocket",
                tomcat.getShellInjectorPair(ShellTool.Proxy, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.injector.tomcat.TomcatRawWsInjector",
                tomcat.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                tomcat.getShellInjectorPair(ShellTool.Command, ShellType.JAKARTA_RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.injector.tomcat.TomcatRawWsInjector",
                tomcat.getShellInjectorPair(ShellTool.Command, ShellType.JAKARTA_RAW_WEBSOCKET).getRight());
    }

    /**
     * JBossWeb 是 Tomcat 分支，JBoss 4~7.1/EAP6 直接复用同一份 RawWebSocket helper。
     */
    @Test
    void testJbossRawWebSocketReusesTomcatHelper() {
        AbstractServer jboss = registry.getServer(Server.JBoss);
        assertNotNull(jboss);
        assertTrue(jboss.getSupportedShellTypes(ShellTool.Command).contains(ShellType.RAW_WEBSOCKET));
        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                jboss.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.injector.tomcat.TomcatRawWsInjector",
                jboss.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getRight());
    }

    /**
     * GlassFish/Payara 的 Grizzly 连接器与 Tomcat coyote 不兼容，RawWebSocket 走
     * 独立的 Grizzly helper 注入器。
     */
    @Test
    void testGlassFishRawWebSocketUsesGrizzlyHelperInjector() {
        AbstractServer glassFish = registry.getServer(Server.GlassFish);
        assertNotNull(glassFish);
        for (String shellType : Arrays.asList(ShellType.RAW_WEBSOCKET, ShellType.JAKARTA_RAW_WEBSOCKET)) {
            assertTrue(glassFish.getSupportedShellTypes(ShellTool.Command).contains(shellType));
            assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                    glassFish.getShellInjectorPair(ShellTool.Command, shellType).getLeft());
            assertEquals("com.reajason.javaweb.memshell.injector.glassfish.GlassFishRawWsInjector",
                    glassFish.getShellInjectorPair(ShellTool.Command, shellType).getRight());
        }
    }

    /**
     * BES/TongWeb 是改了包名的 Tomcat 分支，需要各自的 Filter 注入器先 defineClass helper；
     * helper 实现仍复用 Tomcat 系。
     */
    @Test
    void testTomcatForksRawWebSocketInjectors() {
        assertRawWsInjector(Server.BES, "com.reajason.javaweb.memshell.injector.bes.BesRawWsInjector");
        assertRawWsInjector(Server.TongWeb, "com.reajason.javaweb.memshell.injector.tongweb.TongWebRawWsInjector");
    }

    /**
     * Jetty 的 EndPoint 抽象横跨 Buffer（6/7/8）与 ByteBuffer（9+），RawWebSocket 走
     * 独立的 helper 注入器。
     */
    @Test
    void testJettyRawWebSocketUsesEndpointHelperInjector() {
        assertRawWsInjector(Server.Jetty, "com.reajason.javaweb.memshell.injector.jetty.JettyRawWsInjector");
    }

    /**
     * Undertow 的 RawWebSocket 通过 HttpServerExchange.upgradeChannel 接管
     * XNIO StreamConnection，helper 与注入器都独立于 Tomcat/Grizzly。
     */
    @Test
    void testUndertowRawWebSocketUsesXnioHelperInjector() {
        assertRawWsInjector(Server.Undertow, "com.reajason.javaweb.memshell.injector.undertow.UndertowRawWsInjector");
    }

    /**
     * 传统 WebSphere 7/8.5/9 没有可用的 Servlet 3.1 upgrade 路径，RawWebSocket 由 helper
     * 直接拿连接器 TCP 读写上下文接管 socket；注入器需要先 defineClass helper。
     */
    @Test
    void testWebSphereRawWebSocketUsesConnectorHelperInjector() {
        AbstractServer webSphere = registry.getServer(Server.WebSphere);
        assertNotNull(webSphere);
        for (String shellTool : Arrays.asList(ShellTool.Command, ShellTool.Godzilla, ShellTool.Proxy)) {
            assertTrue(webSphere.getSupportedShellTypes(shellTool).contains(ShellType.RAW_WEBSOCKET),
                    shellTool + " missing RAW_WEBSOCKET");
        }
        assertFalse(webSphere.getSupportedShellTypes(ShellTool.Command).contains(ShellType.JAKARTA_RAW_WEBSOCKET));
        assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                webSphere.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaRawWebSocket",
                webSphere.getShellInjectorPair(ShellTool.Godzilla, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyRawWebSocket",
                webSphere.getShellInjectorPair(ShellTool.Proxy, ShellType.RAW_WEBSOCKET).getLeft());
        assertEquals("com.reajason.javaweb.memshell.injector.websphere.WebSphereRawWsInjector",
                webSphere.getShellInjectorPair(ShellTool.Command, ShellType.RAW_WEBSOCKET).getRight());
    }

    private void assertRawWsInjector(String serverName, String injectorClass) {
        AbstractServer server = registry.getServer(serverName);
        assertNotNull(server, serverName);
        for (String shellType : Arrays.asList(ShellType.RAW_WEBSOCKET, ShellType.JAKARTA_RAW_WEBSOCKET)) {
            assertTrue(server.getSupportedShellTypes(ShellTool.Command).contains(shellType),
                    serverName + " missing " + shellType);
            assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket",
                    server.getShellInjectorPair(ShellTool.Command, shellType).getLeft());
            assertEquals(injectorClass, server.getShellInjectorPair(ShellTool.Command, shellType).getRight());
        }
    }

    private static String shellTemplate(AbstractServer server, String shellTool) {
        Pair<String, String> pair = server.getShellInjectorPair(shellTool, ShellType.WEBSOCKET);
        assertNotNull(pair, server.getClass().getSimpleName() + " has no WebSocket mapping for " + shellTool);
        return pair.getLeft();
    }

    /**
     * WebSocket 走 JSR-356 Endpoint 注册；javax/jakarta 两种壳类型共用同一份 javax 模板，
     * 由生成期统一重命名。
     */
    @Test
    void testWebSocketUsesJsrEndpointTemplate() {
        for (String server : Arrays.asList(Server.Tomcat, Server.Undertow, Server.WebLogic, Server.GlassFish,
                Server.TongWeb, Server.BES, Server.WebSphere, Server.Jetty, Server.InforSuite)) {
            AbstractServer abstractServer = registry.getServer(server);
            assertNotNull(abstractServer, server);
            for (String shellType : Arrays.asList(ShellType.WEBSOCKET, ShellType.JAKARTA_WEBSOCKET)) {
                assertEquals("com.reajason.javaweb.memshell.shelltool.command.CommandWebSocket",
                        abstractServer.getShellInjectorPair(ShellTool.Command, shellType).getLeft());
                assertEquals("com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaWebSocket",
                        abstractServer.getShellInjectorPair(ShellTool.Godzilla, shellType).getLeft());
                assertEquals("com.reajason.javaweb.memshell.shelltool.wsproxy.ProxyWebSocket",
                        abstractServer.getShellInjectorPair(ShellTool.Proxy, shellType).getLeft());
            }
        }
    }

    /**
     * 每个支持 WebSocket 的中间件都必须配上会去 ServletContext 取 ServerContainer
     * 并注册 Endpoint 的注入器，不能退回 Filter 注入。
     */
    @Test
    void testWebSocketInjectorsRegisterEndpoints() {
        for (String server : Arrays.asList(Server.Tomcat, Server.Undertow, Server.WebLogic, Server.GlassFish,
                Server.TongWeb, Server.BES, Server.WebSphere, Server.Jetty, Server.InforSuite)) {
            AbstractServer abstractServer = registry.getServer(server);
            assertNotNull(abstractServer, server);
            String injector = abstractServer.getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight();
            assertTrue(injector.endsWith("WebSocketInjector"),
                    server + " WebSocket injector should register an endpoint, got " + injector);
        }
        assertEquals("com.reajason.javaweb.memshell.injector.undertow.UndertowWebSocketInjector",
                registry.getServer(Server.Undertow)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.glassfish.GlassFishWebSocketInjector",
                registry.getServer(Server.GlassFish)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.tongweb.TongWebWebSocketInjector",
                registry.getServer(Server.TongWeb)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.bes.BesWebSocketInjector",
                registry.getServer(Server.BES)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.websphere.WebSphereWebSocketInjector",
                registry.getServer(Server.WebSphere)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.jetty.JettyWebSocketInjector",
                registry.getServer(Server.Jetty)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteWebSocketInjector",
                registry.getServer(Server.InforSuite)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
        assertEquals("com.reajason.javaweb.memshell.injector.apusic.ApusicWebSocketInjector",
                registry.getServer(Server.Apusic)
                        .getShellInjectorPair(ShellTool.Command, ShellType.WEBSOCKET).getRight());
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
