package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.springwebflux.command.CommandNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaNettyHandler;
import com.reajason.javaweb.memshell.xxljob.injector.XxlJobNettyHandlerInjector;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobShell extends AbstractShell {
    public static final String NETTY_HANDLER = "NettyHandler";

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(NETTY_HANDLER, XxlJobNettyHandlerInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(NETTY_HANDLER, CommandNettyHandler.class).build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(NETTY_HANDLER, GodzillaNettyHandler.class).build());
    }
}
