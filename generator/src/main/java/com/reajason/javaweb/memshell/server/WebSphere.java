package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterChainAgentInjector;
import com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterInjector;
import com.reajason.javaweb.memshell.injector.websphere.WebSphereListenerInjector;
import com.reajason.javaweb.memshell.injector.websphere.WebSphereServletInjector;
import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class WebSphere extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "_connContext"), "_response");
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, WebSphereListenerInjector.class)
                .addInjector(FILTER, WebSphereFilterInjector.class)
                .addInjector(SERVLET, WebSphereServletInjector.class)
                .addInjector(WAS_AGENT_FILTER_MANAGER, WebSphereFilterChainAgentInjector.class)
                .build();
    }
}
