package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.server.*;
import com.reajason.javaweb.memshell.shelltool.antsword.*;
import com.reajason.javaweb.memshell.shelltool.behinder.*;
import com.reajason.javaweb.memshell.shelltool.command.*;
import com.reajason.javaweb.memshell.shelltool.godzilla.*;
import com.reajason.javaweb.memshell.shelltool.neoreg.*;
import com.reajason.javaweb.memshell.shelltool.suo5.*;
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
     * JBoss 中间件，JBoss 6.4-EAP 也使用的当前方式 <a href="https://jbossas.jboss.org/downloads">JBoss AS</a>
     */
    JBoss(new JbossShell()),
    /**
     * Undertow，对应是 Wildfly 以及 JBossEAP7，也有可能是 SpringBoot 用的
     * <a href="https://developers.redhat.com/products/eap/download">JBossEAP</a>
     */
    Undertow(new UndertowShell()),

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

    /**
     * 宝兰德中间件，9.5.2+ 企业版
     */
    BES(new BesShell()),

    /**
     * 东方通中间件
     */
    TongWeb(new TongWebShell()),

    /**
     * 金蝶天燕中间件，only 9
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
                .addShellClass(JETTY_AGENT_HANDLER, GodzillaJettyHandler.class)
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
                .addShellClass(JETTY_AGENT_HANDLER, CommandJettyHandler.class)
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
}