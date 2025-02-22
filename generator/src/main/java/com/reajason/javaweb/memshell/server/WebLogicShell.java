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
public class WebLogicShell extends AbstractShell {

    @Override
    public Class<?> getListenerInterceptor() {
        return TomcatShell.ListenerInterceptor.class;
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, WebLogicServletInjector.class)
                .addInjector(FILTER, WebLogicFilterInjector.class)
                .addInjector(LISTENER, WebLogicListenerInjector.class)
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, WebLogicServletContextAgentInjector.class)
                .build();
    }
}
