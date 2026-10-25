package com.reajason.javaweb.memshell;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * 挂载类型到类名自然后缀的映射。
 * <p>
 * {@link ShellType} 中不少取值是生成器内部的“挂载选择器”，例如 {@code JakartaFilter}、
 * {@code AgentFilterChain}，直接拼到类名里会得到
 * {@code AuthJakartaFilter} 这类一眼假的名字。这里把它们还原成真实项目中常见的类名后缀。
 * <p>
 * 未登记的类型原样返回，保证自定义 ShellTool 仍然可用。
 *
 * @author ReaJason
 */
public final class ShellTypeSuffix {

    private static final Map<String, String> SUFFIXES;

    static {
        Map<String, String> suffixes = new HashMap<>();
        suffixes.put(ShellType.JAKARTA, "Jakarta");
        suffixes.put(ShellType.SERVLET, "Servlet");
        suffixes.put(ShellType.JAKARTA_SERVLET, "Servlet");
        suffixes.put(ShellType.FILTER, "Filter");
        suffixes.put(ShellType.JAKARTA_FILTER, "Filter");
        suffixes.put(ShellType.LISTENER, "Listener");
        suffixes.put(ShellType.JAKARTA_LISTENER, "Listener");
        suffixes.put(ShellType.VALVE, "Valve");
        suffixes.put(ShellType.JAKARTA_VALVE, "Valve");
        suffixes.put(ShellType.UPGRADE, "UpgradeHandler");
        suffixes.put(ShellType.PROXY_VALVE, "Valve");
        suffixes.put(ShellType.JAKARTA_PROXY_VALVE, "Valve");
        suffixes.put(ShellType.HANDLER, "Handler");
        suffixes.put(ShellType.JAKARTA_HANDLER, "Handler");
        suffixes.put(ShellType.CUSTOMIZER, "Customizer");
        suffixes.put(ShellType.NETTY_HANDLER, "Handler");
        suffixes.put(ShellType.AGENT, "Agent");
        suffixes.put(ShellType.AGENT_FILTER_CHAIN, "FilterChain");
        suffixes.put(ShellType.CATALINA_AGENT_CONTEXT_VALVE, "ContextValve");
        suffixes.put(ShellType.JETTY_AGENT_HANDLER, "Handler");
        suffixes.put(ShellType.UNDERTOW_AGENT_SERVLET_HANDLER, "ServletHandler");
        suffixes.put(ShellType.WAS_AGENT_FILTER_MANAGER, "FilterManager");
        suffixes.put(ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT, "ServletContext");
        suffixes.put(ShellType.SPRING_WEBMVC_INTERCEPTOR, "Interceptor");
        suffixes.put(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "Interceptor");
        suffixes.put(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, "Controller");
        suffixes.put(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "Controller");
        suffixes.put(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "Servlet");
        suffixes.put(ShellType.SPRING_WEBFLUX_WEB_FILTER, "WebFilter");
        suffixes.put(ShellType.SPRING_WEBFLUX_HANDLER_METHOD, "Handler");
        suffixes.put(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION, "Handler");
        suffixes.put(ShellType.WEBSOCKET, "WebSocket");
        suffixes.put(ShellType.JAKARTA_WEBSOCKET, "WebSocket");
        suffixes.put(ShellType.RAW_WEBSOCKET, "WebSocket");
        suffixes.put(ShellType.JAKARTA_RAW_WEBSOCKET, "WebSocket");
        suffixes.put(ShellType.ACTION, "Action");
        suffixes.put(ShellType.DUBBO_SERVICE, "Service");
        suffixes.put(ShellType.APACHE_DUBBO_SERVICE, "Service");
        suffixes.put(ShellType.ALIBABA_DUBBO_SERVICE, "Service");
        SUFFIXES = Collections.unmodifiableMap(suffixes);
    }

    private ShellTypeSuffix() {
    }

    /**
     * @param shellType 挂载类型，取值见 {@link ShellType}
     * @return 适合出现在类名末尾的自然后缀；未登记的类型原样返回
     */
    public static String of(String shellType) {
        if (shellType == null) {
            throw new IllegalArgumentException("shellType must not be null");
        }
        String suffix = SUFFIXES.get(shellType);
        return suffix == null ? shellType : suffix;
    }
}
