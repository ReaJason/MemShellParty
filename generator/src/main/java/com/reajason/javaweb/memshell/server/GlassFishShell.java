package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.glassfish.GlassFishContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFishShell extends AbstractShell {

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
                .addInjector(LISTENER, TomcatListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, TomcatListenerInjector.class)
                .addInjector(FILTER, TomcatFilterInjector.class)
                .addInjector(JAKARTA_FILTER, TomcatFilterInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(JAKARTA_VALVE, GlassFishValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, GlassFishFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, GlassFishContextValveAgentInjector.class)
                .build();
    }
}