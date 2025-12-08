package com.reajason.javaweb.memshell;

/**
 * @author ReaJason
 * @since 2024/11/28
 */
public class ShellType {

    public static final String JAKARTA = "Jakarta";
    public static final String SERVLET = "Servlet";
    public static final String JAKARTA_SERVLET = JAKARTA + SERVLET;
    public static final String FILTER = "Filter";
    public static final String JAKARTA_FILTER = JAKARTA + FILTER;
    public static final String LISTENER = "Listener";
    public static final String JAKARTA_LISTENER = JAKARTA + LISTENER;

    public static final String VALVE = "Valve";
    public static final String UPGRADE = "Upgrade";
    public static final String JAKARTA_VALVE = JAKARTA + VALVE;
    public static final String PROXY_VALVE = "Proxy" + VALVE;
    public static final String JAKARTA_PROXY_VALVE = JAKARTA + PROXY_VALVE;

    public static final String HANDLER = "Handler";
    public static final String JAKARTA_HANDLER = JAKARTA + HANDLER;
    public static final String CUSTOMIZER = "Customizer";

    public static final String NETTY_HANDLER = "NettyHandler";

    public static final String AGENT = "Agent";

    public static final String AGENT_FILTER_CHAIN = AGENT + "FilterChain";
    public static final String CATALINA_AGENT_CONTEXT_VALVE = AGENT + "ContextValve";
    public static final String JETTY_AGENT_HANDLER = AGENT + HANDLER;
    public static final String UNDERTOW_AGENT_SERVLET_HANDLER = AGENT + "ServletHandler";
    public static final String WAS_AGENT_FILTER_MANAGER = AGENT + "FilterManager";
    public static final String WEBLOGIC_AGENT_SERVLET_CONTEXT = AGENT + "ServletContext";

    public static final String SPRING_WEBMVC_INTERCEPTOR = "Interceptor";
    public static final String SPRING_WEBMVC_JAKARTA_INTERCEPTOR = "JakartaInterceptor";
    public static final String SPRING_WEBMVC_CONTROLLER_HANDLER = "ControllerHandler";
    public static final String SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER = "JakartaControllerHandler";
    public static final String SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET = AGENT + "FrameworkServlet";

    public static final String SPRING_WEBFLUX_WEB_FILTER = "WebFilter";
    public static final String SPRING_WEBFLUX_HANDLER_METHOD = "HandlerMethod";
    public static final String SPRING_WEBFLUX_HANDLER_FUNCTION = "HandlerFunction";
    public static final String WEBSOCKET = "WebSocket";
    public static final String JAKARTA_WEBSOCKET = "JakartaWebSocket";

    public static final String ACTION = "Action";
}
