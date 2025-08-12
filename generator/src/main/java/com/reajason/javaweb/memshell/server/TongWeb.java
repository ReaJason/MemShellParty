package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.tongweb.*;

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
                .addInjector(LISTENER, TongWebListenerInjector.class)
                .addInjector(FILTER, TongWebFilterInjector.class)
                .addInjector(VALVE, TongWebValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TongWebFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TongWebContextValveAgentInjector.class)
                .build();
    }
}
