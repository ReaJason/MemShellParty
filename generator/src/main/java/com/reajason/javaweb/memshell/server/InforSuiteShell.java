package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.glassfish.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector;
import com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteFilterInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class InforSuiteShell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, InforSuiteFilterInjector.class)
                .addInjector(JAKARTA_FILTER, InforSuiteFilterInjector.class)
                .addInjector(LISTENER, GlassFishListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, GlassFishListenerInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(JAKARTA_VALVE, GlassFishValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .build();
    }
}
