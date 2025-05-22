package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.resin.ResinFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.resin.ResinFilterInjector;
import com.reajason.javaweb.memshell.injector.resin.ResinListenerInjector;
import com.reajason.javaweb.memshell.injector.resin.ResinServletInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class ResinShell extends AbstractShell {

    public static class ListenerInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false, typing = Assigner.Typing.DYNAMIC) Object response) throws Exception {
            response = ShellCommonUtil.getFieldValue(request, "_response");
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, ResinListenerInjector.class)
                .addInjector(FILTER, ResinFilterInjector.class)
                .addInjector(SERVLET, ResinServletInjector.class)
                .addInjector(AGENT_FILTER_CHAIN, ResinFilterChainAgentInjector.class)
                .build();
    }
}
