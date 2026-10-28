package com.reajason.javaweb.memshell.shelltool.proxy;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;

import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 3.0.0
 */
@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ShellTool.Proxy, order = 80)
public class ProxyShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyServlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyFilter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyListener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyValve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyWebSocket")
                .addShellClass(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyWebSocket")
                .addShellClass(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyRawWebSocket")
                .addShellClass(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyRawWebSocket")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyWebFilter")
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHandlerMethod")
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHandlerFunction")
                .addShellClass(NETTY_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyNettyHandler")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyJettyHandler")
                .addShellClass(JAKARTA_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyJettyHandler")
                .addShellClass(CUSTOMIZER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyJettyCustomizer")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyJettyAgentHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyHttp")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyStruts2Action")
                .addShellClass(ALIBABA_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyDubboService")
                .addShellClass(APACHE_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.proxy.ProxyDubboService")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return ProxyConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return ProxyGenerator.class;
    }
}
