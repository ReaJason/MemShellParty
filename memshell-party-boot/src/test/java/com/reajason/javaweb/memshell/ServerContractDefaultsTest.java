package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.glassfish.GlassFish;
import com.reajason.javaweb.memshell.server.jetty.Jetty;
import com.reajason.javaweb.memshell.server.undertow.Undertow;
import com.reajason.javaweb.memshell.server.websphere.WebSphere;
import org.junit.jupiter.api.Test;

import static com.reajason.javaweb.memshell.ShellType.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link AbstractServer#getShellMethodContracts(String)} 默认映射：壳类型决定容器回调入口，
 * 子类不再重复声明；只有 Handler 这类跨中间件语义不同的类型按 Server 覆写。
 */
class ServerContractDefaultsTest {

    private static final AbstractServer BARE = new AbstractServer() {
        @Override
        public InjectorMapping getShellInjectorMapping() {
            return null;
        }
    };

    @Test
    void defaultContractsCoverContainerEntryPoints() {
        assertSame(MethodContracts.FILTER_CONTRACTS, BARE.getShellMethodContracts(FILTER));
        assertSame(MethodContracts.FILTER_CONTRACTS, BARE.getShellMethodContracts(JAKARTA_FILTER));
        assertSame(MethodContracts.FILTER_CONTRACTS, BARE.getShellMethodContracts(AGENT_FILTER_CHAIN));
        assertSame(MethodContracts.FILTER_CONTRACTS, BARE.getShellMethodContracts(WAS_AGENT_FILTER_MANAGER));

        assertSame(MethodContracts.LISTENER_CONTRACTS, BARE.getShellMethodContracts(LISTENER));
        assertSame(MethodContracts.LISTENER_CONTRACTS, BARE.getShellMethodContracts(JAKARTA_LISTENER));

        assertSame(MethodContracts.SERVLET_CONTRACTS, BARE.getShellMethodContracts(SERVLET));
        assertSame(MethodContracts.SERVLET_CONTRACTS, BARE.getShellMethodContracts(JAKARTA_SERVLET));

        assertSame(MethodContracts.VALVE_CONTRACTS, BARE.getShellMethodContracts(VALVE));
        assertSame(MethodContracts.VALVE_CONTRACTS, BARE.getShellMethodContracts(PROXY_VALVE));
        assertSame(MethodContracts.VALVE_CONTRACTS, BARE.getShellMethodContracts(CATALINA_AGENT_CONTEXT_VALVE));
        assertSame(MethodContracts.VALVE_CONTRACTS, BARE.getShellMethodContracts(BYPASS_NGINX_WEBSOCKET));

        assertSame(MethodContracts.WEBSOCKET_CONTRACTS, BARE.getShellMethodContracts(WEBSOCKET));
        assertSame(MethodContracts.UPGRADE_CONTRACTS, BARE.getShellMethodContracts(UPGRADE));

        assertSame(MethodContracts.JETTY_HANDLER_CONTRACTS, BARE.getShellMethodContracts(JETTY_AGENT_HANDLER));
        assertSame(MethodContracts.JETTY_CUSTOMIZER_CONTRACTS, BARE.getShellMethodContracts(CUSTOMIZER));
        assertSame(MethodContracts.UNDERTOW_HANDLER_CONTRACTS, BARE.getShellMethodContracts(UNDERTOW_AGENT_SERVLET_HANDLER));

        assertSame(MethodContracts.SPRING_INTERCEPTOR_CONTRACTS, BARE.getShellMethodContracts(SPRING_WEBMVC_INTERCEPTOR));
        assertSame(MethodContracts.SPRING_CONTROLLER_CONTRACTS, BARE.getShellMethodContracts(SPRING_WEBMVC_CONTROLLER_HANDLER));
        assertSame(MethodContracts.SPRING_FRAMEWORK_SERVLET_CONTRACTS,
                BARE.getShellMethodContracts(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET));
        assertSame(MethodContracts.SPRING_WEBFLUX_FILTER_CONTRACTS, BARE.getShellMethodContracts(SPRING_WEBFLUX_WEB_FILTER));
        assertSame(MethodContracts.SPRING_WEBFLUX_HANDLER_METHOD_CONTRACTS,
                BARE.getShellMethodContracts(SPRING_WEBFLUX_HANDLER_METHOD));
        assertSame(MethodContracts.SPRING_WEBFLUX_HANDLER_FUNCTION_CONTRACTS,
                BARE.getShellMethodContracts(SPRING_WEBFLUX_HANDLER_FUNCTION));
        assertSame(MethodContracts.NETTY_HANDLER_CONTRACTS, BARE.getShellMethodContracts(NETTY_HANDLER));

        assertSame(MethodContracts.DUBBO_CONTRACTS, BARE.getShellMethodContracts(DUBBO_SERVICE));
        assertSame(MethodContracts.DUBBO_CONTRACTS, BARE.getShellMethodContracts(APACHE_DUBBO_SERVICE));
        assertSame(MethodContracts.DUBBO_CONTRACTS, BARE.getShellMethodContracts(ALIBABA_DUBBO_SERVICE));
        assertSame(MethodContracts.STRUTS2_CONTRACTS, BARE.getShellMethodContracts(ACTION));
        assertSame(MethodContracts.WEBLOGIC_AGENT_SERVLET_CONTEXT_CONTRACTS,
                BARE.getShellMethodContracts(WEBLOGIC_AGENT_SERVLET_CONTEXT));
    }

    @Test
    void unknownShellTypeFallsBackToConservative() {
        assertSame(MethodContracts.CONSERVATIVE, BARE.getShellMethodContracts(null));
        assertSame(MethodContracts.CONSERVATIVE, BARE.getShellMethodContracts("NotAShellType"));
    }

    @Test
    void ambiguousHandlerTypeIsResolvedPerServer() {
        // Handler 的入口方法因中间件而异，父类只做保守兜底
        assertSame(MethodContracts.CONSERVATIVE, BARE.getShellMethodContracts(HANDLER));
        assertSame(MethodContracts.CONSERVATIVE, BARE.getShellMethodContracts(JAKARTA_HANDLER));

        Jetty jetty = new Jetty();
        assertSame(MethodContracts.JETTY_HANDLER_CONTRACTS, jetty.getShellMethodContracts(HANDLER));
        assertSame(MethodContracts.JETTY_HANDLER_CONTRACTS, jetty.getShellMethodContracts(JAKARTA_HANDLER));

        Undertow undertow = new Undertow();
        assertSame(MethodContracts.UNDERTOW_HANDLER_CONTRACTS, undertow.getShellMethodContracts(HANDLER));
        assertSame(MethodContracts.UNDERTOW_HANDLER_CONTRACTS, undertow.getShellMethodContracts(JAKARTA_HANDLER));
    }

    @Test
    void osgiAgentShellsForceAesOff() {
        // 默认不覆盖任何选项
        assertTrue(BARE.getShellObfuscationOptionOverrides(WAS_AGENT_FILTER_MANAGER).isEmpty());

        // Open Liberty：shell 定义进 com.ibm.ws.webcontainer 的 Equinox bundle loader
        WebSphere webSphere = new WebSphere();
        assertEquals(Boolean.FALSE,
                webSphere.getShellObfuscationOptionOverrides(WAS_AGENT_FILTER_MANAGER).get("enableAES"));
        assertTrue(webSphere.getShellObfuscationOptionOverrides(FILTER).isEmpty());
        assertTrue(webSphere.getShellObfuscationOptionOverrides(SERVLET).isEmpty());

        // GlassFish/Payara：两种 Agent shell 定义进 Felix bundle loader
        GlassFish glassFish = new GlassFish();
        assertEquals(Boolean.FALSE,
                glassFish.getShellObfuscationOptionOverrides(AGENT_FILTER_CHAIN).get("enableAES"));
        assertEquals(Boolean.FALSE,
                glassFish.getShellObfuscationOptionOverrides(CATALINA_AGENT_CONTEXT_VALVE).get("enableAES"));
        assertTrue(glassFish.getShellObfuscationOptionOverrides(FILTER).isEmpty());
        assertTrue(glassFish.getShellObfuscationOptionOverrides(VALVE).isEmpty());
    }
}
