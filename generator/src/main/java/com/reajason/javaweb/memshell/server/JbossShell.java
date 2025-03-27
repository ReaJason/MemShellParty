package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.jboss.JbossFilterInjector;
import com.reajason.javaweb.memshell.injector.jboss.JbossListenerInjector;
import com.reajason.javaweb.memshell.injector.jboss.JbossValveInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentWithAsmInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentWithAsmInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JbossShell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, JbossFilterInjector.class)
                .addInjector(LISTENER, JbossListenerInjector.class)
                .addInjector(VALVE, JbossValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(AGENT_FILTER_CHAIN_ASM, TomcatFilterChainAgentWithAsmInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE_ASM, TomcatContextValveAgentWithAsmInjector.class)
                .build();
    }
}