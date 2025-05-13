package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.server.*;
import com.reajason.javaweb.memshell.shelltool.antsword.*;
import com.reajason.javaweb.memshell.shelltool.antsword.jetty.AntSwordHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.undertow.AntSwordServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.*;
import com.reajason.javaweb.memshell.shelltool.behinder.jetty.BehinderHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.undertow.BehinderServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.*;
import com.reajason.javaweb.memshell.shelltool.command.jetty.CommandHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.jetty.CommandHandlerAsmMethodVisitor;
import com.reajason.javaweb.memshell.shelltool.command.undertow.CommandServerInitialHandlerAsmMethodVisitor;
import com.reajason.javaweb.memshell.shelltool.command.undertow.CommandServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.jetty.GodzillaHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.undertow.GodzillaServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgFilter;
import com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgListener;
import com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgServlet;
import com.reajason.javaweb.memshell.shelltool.neoreg.NeoreGeorgValve;
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
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.neoreg.NeoreGeorgControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.neoreg.NeoreGeorgInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5ControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5Interceptor;
import lombok.Getter;

import static com.reajason.javaweb.memshell.ShellType.*;
import static com.reajason.javaweb.memshell.server.ServerToolRegistry.addToolMapping;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
@Getter
public enum Server {
    /**
     * Tomcat 中间件
     */
    Tomcat(new TomcatShell()),
    /**
     * Jetty 中间件
     */
    Jetty(new JettyShell()),
    /**
     * JBoss AS 中间件，JBoss 6.4-EAP 也使用的当前方式 <a href="https://jbossas.jboss.org/downloads">JBoss AS</a>
     */
    JBossAS(new JbossShell()),
    JBossEAP6(new JbossShell()),
    /**
     * Undertow，对应是 Wildfly 以及 JBoss EAP，也有可能是 SpringBoot 用的
     * <a href="https://developers.redhat.com/products/eap/download">JBossEAP</a>
     */
    Undertow(new UndertowShell()),
    JBossEAP7(new UndertowShell()),
    WildFly(new UndertowShell()),

    /**
     * SpringMVC 框架
     */
    SpringWebMvc(new SpringWebMvcShell()),

    /**
     * Spring WebFlux 框架
     */
    SpringWebFlux(new SpringWebFluxShell()),

    /**
     * WebSphere 中间件
     */
    WebSphere(new WebSphereShell()),

    /**
     * WebLogic 中间件
     */
    WebLogic(new WebLogicShell()),

    /**
     * Resin 中间件，<a href="https://caucho.com/products/resin/download">Resin</a>
     */
    Resin(new ResinShell()),

    /**
     * GlassFish 中间件
     */
    GlassFish(new GlassFishShell()),
    Payara(new GlassFishShell()),

    /**
     * 宝兰德中间件
     */
    BES(new BesShell()),

    /**
     * 东方通中间件
     */
    TongWeb6(new TongWeb6Shell()),
    TongWeb7(new TongWeb7Shell()),

    /**
     * 金蝶天燕中间件
     */
    Apusic(new ApusicShell()),

    /**
     * 中创中间件
     */
    InforSuite(new InforSuiteShell()),

    /**
     * 普元中间件
     */
    Primeton(new GlassFishShell()),

    /**
     * XXL-JOB
     */
    XXLJOB(new XxlJobShell());

    private final AbstractShell shell;

    Server(AbstractShell shell) {
        this.shell = shell;
    }

    static {
        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(SERVLET, GodzillaServlet.class)
                .addShellClass(JAKARTA_SERVLET, GodzillaServlet.class)
                .addShellClass(FILTER, GodzillaFilter.class)
                .addShellClass(JAKARTA_FILTER, GodzillaFilter.class)
                .addShellClass(LISTENER, GodzillaListener.class)
                .addShellClass(JAKARTA_LISTENER, GodzillaListener.class)
                .addShellClass(VALVE, GodzillaValve.class)
                .addShellClass(JAKARTA_VALVE, GodzillaValve.class)
                .addShellClass(WEBSOCKET, GodzillaWebSocket.class)
                .addShellClass(JAKARTA_WEBSOCKET, GodzillaWebSocket.class)
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

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(SERVLET, AntSwordServlet.class)
                .addShellClass(FILTER, AntSwordFilter.class)
                .addShellClass(LISTENER, AntSwordListener.class)
                .addShellClass(VALVE, AntSwordValve.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, AntSwordServletAdvisor.class)
                .addShellClass(AGENT_FILTER_CHAIN, AntSwordFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, AntSwordFilterChainAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER, AntSwordHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, AntSwordServletInitialHandlerAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, AntSwordFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, AntSwordFilterChainAdvisor.class)
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
                .addShellClass(WEBSOCKET, CommandWebSocket.class)
                .addShellClass(JAKARTA_WEBSOCKET, CommandWebSocket.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, CommandFilterChainAdvisor.class)
                .addShellClass(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET_ASM, CommandFilterChainAsmMethodVisitor.class)
                .addShellClass(SPRING_WEBFLUX_WEB_FILTER, CommandWebFilter.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_METHOD, CommandHandlerMethod.class)
                .addShellClass(SPRING_WEBFLUX_HANDLER_FUNCTION, CommandHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, CommandNettyHandler.class)
                .addShellClass(AGENT_FILTER_CHAIN, CommandFilterChainAdvisor.class)
                .addShellClass(AGENT_FILTER_CHAIN_ASM, CommandFilterChainAsmMethodVisitor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE, CommandFilterChainAdvisor.class)
                .addShellClass(CATALINA_AGENT_CONTEXT_VALVE_ASM, CommandFilterChainAsmMethodVisitor.class)
                .addShellClass(JETTY_AGENT_HANDLER, CommandHandlerAdvisor.class)
                .addShellClass(JETTY_AGENT_HANDLER_ASM, CommandHandlerAsmMethodVisitor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER, CommandServletInitialHandlerAdvisor.class)
                .addShellClass(UNDERTOW_AGENT_SERVLET_HANDLER_ASM, CommandServerInitialHandlerAsmMethodVisitor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT, CommandFilterChainAdvisor.class)
                .addShellClass(WEBLOGIC_AGENT_SERVLET_CONTEXT_ASM, CommandFilterChainAsmMethodVisitor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER, CommandFilterChainAdvisor.class)
                .addShellClass(WAS_AGENT_FILTER_MANAGER_ASM, CommandFilterChainAsmMethodVisitor.class)
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

        addToolMapping(ShellTool.NeoreGeorg, ToolMapping.builder()
                .addShellClass(SERVLET, NeoreGeorgServlet.class)
                .addShellClass(JAKARTA_SERVLET, NeoreGeorgServlet.class)
                .addShellClass(FILTER, NeoreGeorgFilter.class)
                .addShellClass(JAKARTA_FILTER, NeoreGeorgFilter.class)
                .addShellClass(LISTENER, NeoreGeorgListener.class)
                .addShellClass(JAKARTA_LISTENER, NeoreGeorgListener.class)
                .addShellClass(VALVE, NeoreGeorgValve.class)
                .addShellClass(JAKARTA_VALVE, NeoreGeorgValve.class)
                .addShellClass(SPRING_WEBMVC_INTERCEPTOR, NeoreGeorgInterceptor.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, NeoreGeorgInterceptor.class)
                .addShellClass(SPRING_WEBMVC_CONTROLLER_HANDLER, NeoreGeorgControllerHandler.class)
                .addShellClass(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, NeoreGeorgControllerHandler.class)
                .build());
    }
}