package com.reajason.javaweb.memshell.shelltool.godzilla;

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
@ShellToolMeta(name = ShellTool.Godzilla, order = 10)
public class GodzillaShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaListener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaWebSocket")
                .addShellClass(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaWebSocket")
                .addShellClass(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaRawWebSocket")
                .addShellClass(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaRawWebSocket")
                .addShellClass(UPGRADE, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaUpgrade")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaWebFilter")
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaHandlerMethod")
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaHandlerFunction")
                .addShellClass(NETTY_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaNettyHandler")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaJettyHandler")
                .addShellClass(JAKARTA_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaJettyHandler")
                .addShellClass(CUSTOMIZER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaJettyCustomizer")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaJettyAgentHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.godzilla.Godzilla")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaStruts2Action")
                .addShellClass(ALIBABA_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaDubboService")
                .addShellClass(APACHE_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaDubboService")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return GodzillaConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return GodzillaGenerator.class;
    }
}
