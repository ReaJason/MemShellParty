package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;
import org.kohsuke.MetaInfServices;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 3.0.0
 */
@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ShellTool.Command, order = 30)
public class CommandShellToolProvider implements ShellToolProvider {

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(SERVLET, "com.reajason.javaweb.memshell.shelltool.command.CommandServlet")
                .addShellClass(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.shelltool.command.CommandServlet")
                .addShellClass(FILTER, "com.reajason.javaweb.memshell.shelltool.command.CommandFilter")
                .addShellClass(JAKARTA_FILTER, "com.reajason.javaweb.memshell.shelltool.command.CommandFilter")
                .addShellClass(LISTENER, "com.reajason.javaweb.memshell.shelltool.command.CommandListener")
                .addShellClass(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.shelltool.command.CommandListener")
                .addShellClass(VALVE, "com.reajason.javaweb.memshell.shelltool.command.CommandValve")
                .addShellClass(JAKARTA_VALVE, "com.reajason.javaweb.memshell.shelltool.command.CommandValve")
                .addShellClass(PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.command.CommandWebSocket")
                .addShellClass(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.command.CommandWebSocket")
                .addShellClass(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket")
                .addShellClass(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.shelltool.command.CommandRawWebSocket")
                .addShellClass(UPGRADE, "com.reajason.javaweb.memshell.shelltool.command.CommandUpgrade")
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.command.CommandInterceptor")
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.shelltool.command.CommandInterceptor")
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandControllerHandler")
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandControllerHandler")
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, "com.reajason.javaweb.memshell.shelltool.command.CommandWebFilter")
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, "com.reajason.javaweb.memshell.shelltool.command.CommandHandlerMethod")
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, "com.reajason.javaweb.memshell.shelltool.command.CommandHandlerFunction")
                .addShellClass(NETTY_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandNettyHandler")
                .addShellClass(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(JETTY_AGENT_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandJettyAgentHandler")
                .addShellClass(HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandJettyHandler")
                .addShellClass(CUSTOMIZER, "com.reajason.javaweb.memshell.shelltool.command.CommandJettyCustomizer")
                .addShellClass(JAKARTA_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandJettyHandler")
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.shelltool.command.CommandUndertowServletHandler")
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.shelltool.command.Command")
                .addShellClass(ACTION, "com.reajason.javaweb.memshell.shelltool.command.CommandStruts2Action")
                .addShellClass(ALIBABA_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.command.CommandDubboService")
                .addShellClass(APACHE_DUBBO_SERVICE, "com.reajason.javaweb.memshell.shelltool.command.CommandDubboService")
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return CommandConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return CommandGenerator.class;
    }
}
