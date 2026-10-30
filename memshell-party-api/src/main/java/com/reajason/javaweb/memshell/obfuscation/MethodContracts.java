package com.reajason.javaweb.memshell.obfuscation;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * 常用方法契约集合。
 *
 * @author ReaJason
 */
public final class MethodContracts {

    private MethodContracts() {
    }

    /**
     * Injector 通用入口与反射调用的方法契约
     */
    public static final Set<MethodSignature> INJECTOR_COMMON = Collections.unmodifiableSet(
            signatures(
                    "getUrlPattern",
                    "getClassName",
                    "getBase64String",
                    "getHelperBase64String",
                    "premain",
                    "agentmain",
                    "transform",
                    // 容器/框架回调：XxlJob 的 Netty ChannelInitializer、Spring WebFlux 的
                    // ChannelPipelineConfigurer、Tomcat ProxyValve 的 InvocationHandler
                    "initChannel",
                    "onChannelInit",
                    "invoke",
                    "main",
                    // probe 回显通过 injector.toString() 取注入日志，必须保住重写关系；
                    // 此前仅靠 autoDisableImpl 对父类 Object 的顺带保护，关掉该选项或
                    // 父类在生成侧不可加载时 toString 会被改名，回显退化成默认对象串
                    "toString",
                    "equals",
                    "hashCode"
            )
    );

    /**
     * Probe 回显马通用入口契约
     */
    public static final Set<MethodSignature> PROBE_COMMON = Collections.unmodifiableSet(
            signatures(
                    "toString",
                    "equals",
                    "hashCode",
                    "doFilter",
                    "init",
                    "destroy",
                    "getUrlPattern"
            )
    );

    /**
     * Object 方法：Agent 注入器通过 {@code INVOKEVIRTUAL java/lang/Object.equals} 触发内存马，
     * 因此所有可能被 Agent 注入的马都必须保留 equals；toString/hashCode 一并保留，避免调试/容器
     * 日志路径出现意外行为。
     */
    public static final Set<MethodSignature> OBJECT_CONTRACTS = Collections.unmodifiableSet(
            signatures("equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> FILTER_CONTRACTS = Collections.unmodifiableSet(
            signatures("doFilter", "init", "destroy", "equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> SERVLET_CONTRACTS = Collections.unmodifiableSet(
            signatures("service", "doGet", "doPost", "init", "destroy")
    );

    public static final Set<MethodSignature> LISTENER_CONTRACTS = Collections.unmodifiableSet(
            signatures("requestInitialized", "requestDestroyed")
    );

    public static final Set<MethodSignature> VALVE_CONTRACTS = Collections.unmodifiableSet(
            signatures("invoke", "getNext", "setNext", "isAsyncSupported", "backgroundProcess",
                    "equals", "hashCode", "toString")
    );

    /**
     * WebSocket 壳是 JSR-356 {@code Endpoint}，由容器通过 {@code ServerContainer} 回调。
     */
    public static final Set<MethodSignature> WEBSOCKET_CONTRACTS = Collections.unmodifiableSet(
            signatures("onOpen", "onClose", "onError", "onMessage", "modifyHandshake")
    );

    /**
     * RawWebSocket 壳是 Filter，握手与帧协议由 helper 接管；helper 通过反射回调
     * onStart/onReadBinary/onReadText/onDisconnect，这些入口都不能被改名。
     */
    public static final Set<MethodSignature> RAW_WEBSOCKET_CONTRACTS = Collections.unmodifiableSet(
            signatures("doFilter", "init", "destroy",
                    "onStart", "onReadBinary", "onReadText", "onDisconnect",
                    "equals", "hashCode", "toString")
    );

    /**
     * RawWebSocket 壳通过字符串反射调用 helper，直接字节码引用扫描无法发现这些入口。
     */
    public static final Set<MethodSignature> RAW_WEBSOCKET_HELPER_CONTRACTS = Collections.unmodifiableSet(
            signatures("sendText", "sendBinary", "getAttribute", "setAttribute", "startPump",
                    "run", "close", "equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> UPGRADE_CONTRACTS = Collections.unmodifiableSet(
            signatures("accept", "getHttpUpgradeName", "getAlpnIdentifier", "getAlpnName",
                    "getProcessor", "getInternalUpgradeHandler")
    );

    public static final Set<MethodSignature> JETTY_HANDLER_CONTRACTS = Collections.unmodifiableSet(
            signatures("handle", "equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> JETTY_CUSTOMIZER_CONTRACTS = Collections.unmodifiableSet(
            signatures("customize")
    );

    public static final Set<MethodSignature> UNDERTOW_HANDLER_CONTRACTS = Collections.unmodifiableSet(
            signatures("handleRequest", "equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> SPRING_INTERCEPTOR_CONTRACTS = Collections.unmodifiableSet(
            signatures("preHandle", "postHandle", "afterCompletion")
    );

    public static final Set<MethodSignature> SPRING_CONTROLLER_CONTRACTS = Collections.unmodifiableSet(
            signatures("handleRequest")
    );

    /**
     * Spring WebMvc Agent FrameworkServlet：直接替换容器 DispatcherServlet，同时覆盖
     * Interceptor 与 HttpServlet 两条回调路径。
     */
    public static final Set<MethodSignature> SPRING_FRAMEWORK_SERVLET_CONTRACTS = Collections.unmodifiableSet(
            signatures("preHandle", "postHandle", "afterCompletion",
                    "doService", "service", "equals", "hashCode", "toString")
    );

    /**
     * WebLogic Agent ServletContext：Filter 与 Servlet 两条入口都可能被容器调用。
     */
    public static final Set<MethodSignature> WEBLOGIC_AGENT_SERVLET_CONTEXT_CONTRACTS = Collections.unmodifiableSet(
            signatures("doFilter", "service", "equals", "hashCode", "toString")
    );

    public static final Set<MethodSignature> SPRING_WEBFLUX_FILTER_CONTRACTS = Collections.unmodifiableSet(
            signatures("filter")
    );

    public static final Set<MethodSignature> SPRING_WEBFLUX_HANDLER_METHOD_CONTRACTS = Collections.unmodifiableSet(
            signatures("invoke")
    );

    public static final Set<MethodSignature> SPRING_WEBFLUX_HANDLER_FUNCTION_CONTRACTS = Collections.unmodifiableSet(
            signatures("handle")
    );

    public static final Set<MethodSignature> NETTY_HANDLER_CONTRACTS = Collections.unmodifiableSet(
            signatures("channelRead", "channelRead0", "handlerAdded", "handlerRemoved", "exceptionCaught")
    );

    public static final Set<MethodSignature> DUBBO_CONTRACTS = Collections.unmodifiableSet(
            signatures("invoke", "handle")
    );

    public static final Set<MethodSignature> STRUTS2_CONTRACTS = Collections.unmodifiableSet(
            signatures("execute", "intercept")
    );

    /**
     * 保守模式契约：汇总所有已知容器规范入口（Servlet/Filter/Valve/Handler/WebSocket/Agent 等）
     */
    public static final Set<MethodSignature> CONSERVATIVE = Collections.unmodifiableSet(
            signatures(
                    // Filter
                    "doFilter",
                    "init",
                    "destroy",
                    // Servlet
                    "service",
                    "doGet",
                    "doPost",
                    "doPut",
                    "doDelete",
                    "doHead",
                    "doOptions",
                    "doTrace",
                    "getServletConfig",
                    "getServletInfo",
                    // Valve
                    "invoke",
                    "getNext",
                    "setNext",
                    "isAsyncSupported",
                    "backgroundProcess",
                    // Listener
                    "requestInitialized",
                    "requestDestroyed",
                    "sessionCreated",
                    "sessionDestroyed",
                    "contextInitialized",
                    "contextDestroyed",
                    "attributeAdded",
                    "attributeRemoved",
                    "attributeReplaced",
                    // Handler (Jetty / Spring / Undertow)
                    "handle",
                    "handleRequest",
                    "customize",
                    // Interceptor / Spring Controller / WebFlux
                    "preHandle",
                    "postHandle",
                    "afterCompletion",
                    "filter",
                    "doService",
                    // Upgrade (Tomcat)
                    "accept",
                    "getHttpUpgradeName",
                    "getAlpnIdentifier",
                    "getAlpnName",
                    "getProcessor",
                    "getInternalUpgradeHandler",
                    "getReadListener",
                    "getWriteListener",
                    "onDataAvailable",
                    "onAllDataRead",
                    "onError",
                    // Netty Handler
                    "channelRead",
                    "channelRead0",
                    "handlerAdded",
                    "handlerRemoved",
                    "exceptionCaught",
                    "initChannel",
                    "onChannelInit",
                    // WebSocket
                    "onOpen",
                    "onClose",
                    "onMessage",
                    "modifyHandshake",
                    // RawWebSocket helper 回调
                    "onStart",
                    "onReadBinary",
                    "onReadText",
                    "onDisconnect",
                    // Agent 与持久化伴随类
                    "premain",
                    "agentmain",
                    "transform",
                    "persist",
                    "isPersistent",
                    // Runnable/RawWebSocket helper
                    "run",
                    "close",
                    // Struts2 / XXL-Job / Dubbo
                    "execute",
                    "intercept",
                    // Object
                    "toString",
                    "equals",
                    "hashCode",
                    "clone",
                    "main"
            )
    );

    public static Set<MethodSignature> signatures(String... names) {
        Set<MethodSignature> set = new LinkedHashSet<MethodSignature>();
        if (names != null) {
            for (String name : names) {
                if (name != null && !name.trim().isEmpty()) {
                    set.add(MethodSignature.anyOverload(name.trim()));
                }
            }
        }
        return set;
    }

    private static Set<MethodSignature> union(Set<MethodSignature> first, Set<MethodSignature> second) {
        Set<MethodSignature> set = new LinkedHashSet<MethodSignature>(first);
        set.addAll(second);
        return set;
    }

    public static Set<MethodSignature> of(MethodSignature... signatures) {
        if (signatures == null || signatures.length == 0) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(new LinkedHashSet<MethodSignature>(Arrays.asList(signatures)));
    }
}
