package com.reajason.javaweb.memshell.injector.tomcat;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * Godzilla 4.15 内置 WebSocket 通道连接的是 {@code <urlPattern>/<pass>}，而 GzWebsocket 插件
 * 直接用配置的 URL，注入器要为同一 shell 同时挂两种入口。
 *
 * @author ReaJason
 */
class WebSocketSuffixMappingTest {

    @Test
    void rawWsFilterAddsPrefixMapping() {
        assertEquals("/gz/*", TomcatRawWsInjector.getSuffixUrlPattern("/gz"));
        assertEquals("/gz/*", TomcatRawWsInjector.getSuffixUrlPattern("/gz/"));
        assertEquals("/*", TomcatRawWsInjector.getSuffixUrlPattern("/"));
    }

    @Test
    void rawWsFilterSkipsMappingsThatAlreadyCoverSubPaths() {
        assertNull(TomcatRawWsInjector.getSuffixUrlPattern("/*"));
        assertNull(TomcatRawWsInjector.getSuffixUrlPattern("/gz/*"));
        assertNull(TomcatRawWsInjector.getSuffixUrlPattern("*.jsp"));
        assertNull(TomcatRawWsInjector.getSuffixUrlPattern(null));
        assertNull(TomcatRawWsInjector.getSuffixUrlPattern(""));
    }

    @Test
    void webSocketEndpointAddsUriTemplate() {
        assertEquals("/gz/{pass}", TomcatWebSocketInjector.getSuffixEndpointPath("/gz"));
        assertEquals("/gz/{pass}", TomcatWebSocketInjector.getSuffixEndpointPath("/gz/"));
    }

    @Test
    void webSocketEndpointSkipsWildcards() {
        assertNull(TomcatWebSocketInjector.getSuffixEndpointPath("/*"));
        assertNull(TomcatWebSocketInjector.getSuffixEndpointPath(null));
        assertNull(TomcatWebSocketInjector.getSuffixEndpointPath(""));
    }
}
