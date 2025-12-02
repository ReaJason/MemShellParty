package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.server.*;
import com.reajason.javaweb.memshell.shelltool.antsword.*;
import com.reajason.javaweb.memshell.shelltool.behinder.*;
import com.reajason.javaweb.memshell.shelltool.command.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.*;
import com.reajason.javaweb.memshell.shelltool.neoreg.*;
import com.reajason.javaweb.memshell.shelltool.suo5.*;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2025/8/11
 */
public class ServerFactory {
    private static final Map<String, Supplier<AbstractServer>> registry = new ConcurrentHashMap<>();
    private static final Map<String, AbstractServer> instances = new ConcurrentHashMap<>();
    private static final List<String> servers = new CopyOnWriteArrayList<>();

    static {
        register(Server.Tomcat, Tomcat::new);
        register(Server.Jetty, Jetty::new);
        register(Server.Undertow, Undertow::new);
        register(Server.JBoss, Jboss::new);
        register(Server.Resin, Resin::new);
        register(Server.WebLogic, WebLogic::new);
        register(Server.WebSphere, WebSphere::new);
        register(Server.GlassFish, GlassFish::new);
        register(Server.TongWeb, TongWeb::new);
        register(Server.BES, Bes::new);
        register(Server.InforSuite, InforSuite::new);
        register(Server.Apusic, Apusic::new);
        register(Server.SpringWebMvc, SpringWebMvc::new);
        register(Server.SpringWebFlux, SpringWebFlux::new);
        register(Server.XXLJOB, XxlJob::new);

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, GodzillaListener.class)
                .addShellClass(JAKARTA_LISTENER, GodzillaListener.class)
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve.class)
                .addShellClass(PROXY_VALVE, Godzilla.class)
                .addShellClass(JAKARTA_PROXY_VALVE, Godzilla.class)
                .addShellClass(WEBSOCKET, GodzillaWebSocket.class)
                .addShellClass(JAKARTA_WEBSOCKET, GodzillaWebSocket.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, Godzilla.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, GodzillaWebFilter.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, GodzillaHandlerMethod.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, GodzillaHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, GodzillaNettyHandler.class)
                .addShellClass(AGENT_FILTER_CHAIN, Godzilla.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, Godzilla.class)
                .addShellClass(HANDLER, GodzillaJettyHandler.class)
                .addShellClass(JAKARTA_HANDLER, GodzillaJettyHandler.class)
                .addShellClass(CUSTOMIZER, GodzillaJettyCustomizer.class)
                .addShellClass(JETTY_AGENT_HANDLER, GodzillaJettyAgentHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, GodzillaUndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, Godzilla.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, Godzilla.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(SERVLET, BehinderServlet.class)
                .addShellClass(JAKARTA_SERVLET, BehinderServlet.class)
                .addShellClass(FILTER, BehinderFilter.class)
                .addShellClass(JAKARTA_FILTER, BehinderFilter.class)
                .addShellClass(LISTENER, BehinderListener.class)
                .addShellClass(JAKARTA_LISTENER, BehinderListener.class)
                .addShellClass(VALVE, BehinderValve.class)
                .addShellClass(JAKARTA_VALVE, BehinderValve.class)
                .addShellClass(PROXY_VALVE, Behinder.class)
                .addShellClass(JAKARTA_PROXY_VALVE, Behinder.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, Behinder.class)
                .addShellClass(AGENT_FILTER_CHAIN, Behinder.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, Behinder.class)
                .addShellClass(JETTY_AGENT_HANDLER, BehinderJettyHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, BehinderUndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, Behinder.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, Behinder.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, AntSwordListener.class)
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(PROXY_VALVE, AntSword.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, AntSword.class)
                .addShellClass(AGENT_FILTER_CHAIN, AntSword.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSword.class)
                .addShellClass(JETTY_AGENT_HANDLER, AntSwordJettyHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, AntSwordUndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, AntSword.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, AntSword.class)
                .build());

        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(JAKARTA_SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, CommandListener.class)
                .addShellClass(JAKARTA_LISTENER, CommandListener.class)
                .addShellClass(VALVE, CommandValve.class)
                .addShellClass(JAKARTA_VALVE, CommandValve.class)
                .addShellClass(PROXY_VALVE, Command.class)
                .addShellClass(JAKARTA_PROXY_VALVE, Command.class)
                .addShellClass(WEBSOCKET, CommandWebSocket.class)
                .addShellClass(JAKARTA_WEBSOCKET, CommandWebSocket.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, Command.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, CommandWebFilter.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, CommandHandlerMethod.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, CommandHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, CommandNettyHandler.class)
                .addShellClass(AGENT_FILTER_CHAIN, Command.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, Command.class)
                .addShellClass(JETTY_AGENT_HANDLER, CommandJettyAgentHandler.class)
                .addShellClass(HANDLER, CommandJettyHandler.class)
                .addShellClass(CUSTOMIZER, CommandJettyCustomizer.class)
                .addShellClass(JAKARTA_HANDLER, CommandJettyHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, CommandUndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, Command.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, Command.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(SERVLET, Suo5Servlet.class)
                .addShellClass(JAKARTA_SERVLET, Suo5Servlet.class)
                .addShellClass(FILTER, Suo5Filter.class)
                .addShellClass(JAKARTA_FILTER, Suo5Filter.class)
                .addShellClass(LISTENER, Suo5Listener.class)
                .addShellClass(JAKARTA_LISTENER, Suo5Listener.class)
                .addShellClass(VALVE, Suo5Valve.class)
                .addShellClass(JAKARTA_VALVE, Suo5Valve.class)
                .addShellClass(PROXY_VALVE, Suo5.class)
                .addShellClass(JAKARTA_PROXY_VALVE, Suo5.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, Suo5.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, Suo5WebFilter.class)
                .addShellClass(AGENT_FILTER_CHAIN, Suo5.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, Suo5.class)
                .addShellClass(JETTY_AGENT_HANDLER, Suo5JettyHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, Suo5UndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, Suo5.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, Suo5.class)
                .build());

        addToolMapping(ShellTool.NeoreGeorg, ToolMapping.builder()
                .addShellClass(SERVLET, NeoreGeorgServlet.class)
                .addShellClass(JAKARTA_SERVLET, NeoreGeorgServlet.class)
                .addShellClass(FILTER, NeoreGeorgFilter.class)
                .addShellClass(JAKARTA_FILTER, NeoreGeorgFilter.class)
                .addShellClass(LISTENER, NeoreGeorgListener.class)
                .addShellClass(JAKARTA_LISTENER, NeoreGeorgListener.class)
                .addShellClass(VALVE, NeoreGeorgValve.class)
                .addShellClass(JAKARTA_VALVE, NeoreGeorgValve.class)
                .addShellClass(PROXY_VALVE, NeoreGeorg.class)
                .addShellClass(JAKARTA_PROXY_VALVE, NeoreGeorg.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, NeoreGeorgInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, NeoreGeorgInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, NeoreGeorgControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, NeoreGeorgControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, NeoreGeorg.class)
                .addShellClass(AGENT_FILTER_CHAIN, NeoreGeorg.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, NeoreGeorg.class)
                .addShellClass(JETTY_AGENT_HANDLER, NeoreGeorgJettyHandler.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, NeoreGeorgUndertowServletHandler.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, NeoreGeorg.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, NeoreGeorg.class)
                .build());
    }

    public static void register(String serverName, Supplier<AbstractServer> shellSupplier) {
        if (serverName == null || serverName.trim().isEmpty()) {
            throw new IllegalArgumentException("Server name cannot be null or empty.");
        }
        Supplier<AbstractServer> existing = registry.putIfAbsent(serverName, shellSupplier);
        if (existing == null) {
            servers.add(serverName);
        }
    }

    public static AbstractServer getServer(String serverName) {
        if (serverName == null) {
            return null;
        }
        return instances.computeIfAbsent(serverName, k -> {
            Supplier<AbstractServer> supplier = registry.get(k);
            if (supplier == null) {
                throw new IllegalArgumentException("Unsupported server type: '" + serverName + "'.");
            }
            return supplier.get();
        });
    }

    public static void addToolMapping(String shellTool, ToolMapping toolMapping) {
        Map<String, Class<?>> rawToolMapping = toolMapping.getShellClassMap();
        List<String> supportedServers = ServerFactory.getSupportedServers();
        for (String supportedServer : supportedServers) {
            AbstractServer server = ServerFactory.getServer(supportedServer);
            InjectorMapping shellInjectorMapping = server.getShellInjectorMapping();
            Set<String> injectorSupportedShellTypes = shellInjectorMapping.getSupportedShellTypes();
            ToolMapping.ToolMappingBuilder toolMappingBuilder = ToolMapping.builder();

            for (String shellType : injectorSupportedShellTypes) {
                Class<?> shellClass = rawToolMapping.get(shellType);
                if (shellClass == null) {
                    continue;
                }
                toolMappingBuilder.addShellClass(shellType, shellClass);
            }
            ToolMapping mapping = toolMappingBuilder.build();
            if (mapping.isNotEmpty()) {
                server.addToolMapping(shellTool, mapping);
            }
        }
    }

    public static List<String> getSupportedServers() {
        return Collections.unmodifiableList(servers);
    }
}
