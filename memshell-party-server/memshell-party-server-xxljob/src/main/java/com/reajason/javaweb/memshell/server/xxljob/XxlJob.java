package com.reajason.javaweb.memshell.server.xxljob;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;


import static com.reajason.javaweb.memshell.ShellType.NETTY_HANDLER;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJob extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(NETTY_HANDLER, "com.reajason.javaweb.memshell.injector.xxljob.XxlJobNettyHandlerInjector")
                .build();
    }
}
