package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.weblogic.WebLogicFilterInjector;
import com.reajason.javaweb.memshell.injector.weblogic.WebLogicListenerInjector;
import com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletContextAgentInjector;
import com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class WebLogic extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, WebLogicListenerInjector.class)
                .addInjector(FILTER, WebLogicFilterInjector.class)
                .addInjector(SERVLET, WebLogicServletInjector.class)
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, WebLogicServletContextAgentInjector.class)
                .build();
    }
}
