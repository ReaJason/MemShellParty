package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.tongweb.*;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class TongWeb6Shell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, TongWebFilterInjector.class)
                .addInjector(JAKARTA_FILTER, TongWebFilterInjector.class)
                .addInjector(LISTENER, TongWebListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TongWebListenerInjector.class)
                .addInjector(VALVE, TongWebValveInjector.class)
                .addInjector(JAKARTA_VALVE, TongWebValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TongWebFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TongWebContextValveAgentInjector.class)
                .build();
    }
}
