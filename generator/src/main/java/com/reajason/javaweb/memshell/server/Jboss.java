package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.glassfish.GlassFishContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatProxyValveInjector;

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
                .addInjector(LISTENER, TomcatListenerInjector.class)
                .addInjector(FILTER, TomcatFilterInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(PROXY_VALVE, TomcatProxyValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, GlassFishFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, GlassFishContextValveAgentInjector.class)
                .build();
    }
}