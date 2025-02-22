package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.xxljob.injector.XxlJobNettyHandlerInjector;

import static com.reajason.javaweb.memshell.ShellType.NETTY_HANDLER;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobShell extends AbstractShell {

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(NETTY_HANDLER, XxlJobNettyHandlerInjector.class)
                .build();
    }
}
