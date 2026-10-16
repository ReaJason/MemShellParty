package com.reajason.javaweb.memshell.server.weblogic;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;


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
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicWebSocketInjector")
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletContextAgentInjector")
                .build();
    }
}
