package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.bes.*;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class BesShell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, BesFilterInjector.class)
                .addInjector(LISTENER, BesListenerInjector.class)
                .addInjector(VALVE, BesValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, BesFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, BesContextValveAgentInjector.class)
                .build();
    }
}
