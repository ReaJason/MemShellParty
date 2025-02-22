package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.shelltool.antsword.*;
import com.reajason.javaweb.memshell.shelltool.antsword.jetty.AntSwordHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.undertow.AntSwordServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.*;
import com.reajason.javaweb.memshell.shelltool.behinder.jetty.BehinderHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.undertow.BehinderServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.*;
import com.reajason.javaweb.memshell.shelltool.command.jetty.CommandHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.undertow.CommandServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.jetty.GodzillaHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.undertow.GodzillaServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Listener;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.command.CommandNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.command.CommandWebFilter;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaWebFilter;
import com.reajason.javaweb.memshell.springwebflux.suo5.Suo5WebFilter;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5ControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5Interceptor;

import static com.reajason.javaweb.memshell.ShellType.*;
import static com.reajason.javaweb.memshell.server.ServerToolRegistry.addToolMapping;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public enum ShellTool {
    /**
     * 哥斯拉
     */
    Godzilla,

    /**
     * 命令回显
     */
    Command,

    /**
     * 冰蝎
     */
    Behinder,

    /**
     * Suo5 隧道代理
     */
    Suo5,

    /**
     * 蚁剑
     */
    AntSword,

    ;


    static {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(SERVLET, CommandServlet.class)
                .addShellClass(JAKARTA_SERVLET, CommandServlet.class)
                .addShellClass(FILTER, CommandFilter.class)
                .addShellClass(JAKARTA_FILTER, CommandFilter.class)
                .addShellClass(LISTENER, CommandListener.class)
                .addShellClass(JAKARTA_LISTENER, CommandListener.class)
                .addShellClass(VALVE, CommandValve.class)
                .addShellClass(JAKARTA_VALVE, CommandValve.class)
                .addShellClass(WEBSOCKET, CommandWebSocket.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, CommandServletAdvisor.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, CommandWebFilter.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, CommandHandlerMethod.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, CommandHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, CommandNettyHandler.class)
                .addShellClass(AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER, CommandHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, CommandServletInitialHandlerAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, CommandFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, CommandFilterChainAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, GodzillaListener.class)
                .addShellClass(JAKARTA_LISTENER, GodzillaListener.class)
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, GodzillaServletAdvisor.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, GodzillaWebFilter.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, GodzillaHandlerMethod.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, GodzillaHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, GodzillaNettyHandler.class)
                .addShellClass(AGENT_FILTER_CHAIN, GodzillaFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, GodzillaFilterChainAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER, GodzillaHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, GodzillaServletInitialHandlerAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, GodzillaFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, GodzillaFilterChainAdvisor.class)
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
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, BehinderServletAdvisor.class)
                .addShellClass(AGENT_FILTER_CHAIN, BehinderFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, BehinderFilterChainAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER, BehinderHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, BehinderServletInitialHandlerAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, BehinderFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, BehinderFilterChainAdvisor.class)
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
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, Suo5WebFilter.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, AntSwordListener.class)
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, AntSwordServletAdvisor.class)
                .addShellClass(AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER, AntSwordHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, AntSwordServletInitialHandlerAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, AntSwordFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, AntSwordFilterChainAdvisor.class)
                .build());
    }
}
