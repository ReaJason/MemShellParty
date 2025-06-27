package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.glassfish.GlassFishContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector;
import com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteFilterInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector;

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
                .addInjector(LISTENER, TomcatListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TomcatListenerInjector.class)
                .addInjector(FILTER, InforSuiteFilterInjector.class)
                .addInjector(JAKARTA_FILTER, InforSuiteFilterInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(JAKARTA_VALVE, GlassFishValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, GlassFishFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, GlassFishContextValveAgentInjector.class)
                .build();
    }
}
