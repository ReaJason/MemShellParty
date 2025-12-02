package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.jetty.*;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class Jetty extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_channel"), "_response");
            } catch (Exception e) {
                try {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connection"), "_response");
                } catch (Exception ex) {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_servletChannel"), "_response"), "_servletApiResponse");
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
                .addInjector(LISTENER, JettyListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, JettyListenerInjector.class)
                .addInjector(FILTER, JettyFilterInjector.class)
                .addInjector(JAKARTA_FILTER, JettyFilterInjector.class)
                .addInjector(SERVLET, JettyServletInjector.class)
                .addInjector(JAKARTA_SERVLET, JettyServletInjector.class)
                .addInjector(HANDLER, JettyHandlerInjector.class)
                .addInjector(JAKARTA_HANDLER, JettyHandlerInjector.class)
                .addInjector(CUSTOMIZER, JettyCustomizerInjector.class)
                .addInjector(JETTY_AGENT_HANDLER, JettyHandlerAgentInjector.class)
                .build();
    }
}
