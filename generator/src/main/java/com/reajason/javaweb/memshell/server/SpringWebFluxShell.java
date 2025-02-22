package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.command.CommandNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.command.CommandWebFilter;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaWebFilter;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerFunctionInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerMethodInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxNettyHandlerInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxWebFilterInjector;
import com.reajason.javaweb.memshell.springwebflux.suo5.Suo5WebFilter;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class SpringWebFluxShell extends AbstractShell {
    public static final String WEB_FILTER = "WebFilter";
    public static final String HANDLER_METHOD = "HandlerMethod";
    public static final String HANDLER_FUNCTION = "HandlerFunction";
    public static final String NETTY_HANDLER = "NettyHandler";

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(WEB_FILTER, SpringWebFluxWebFilterInjector.class)
                .addInjector(HANDLER_METHOD, SpringWebFluxHandlerMethodInjector.class)
                .addInjector(HANDLER_FUNCTION, SpringWebFluxHandlerFunctionInjector.class)
                .addInjector(NETTY_HANDLER, SpringWebFluxNettyHandlerInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(WEB_FILTER, CommandWebFilter.class)
                .addShellClass(HANDLER_METHOD, CommandHandlerMethod.class)
                .addShellClass(HANDLER_FUNCTION, CommandHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, CommandNettyHandler.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(WEB_FILTER, GodzillaWebFilter.class)
                .addShellClass(HANDLER_METHOD, GodzillaHandlerMethod.class)
                .addShellClass(HANDLER_FUNCTION, GodzillaHandlerFunction.class)
                .addShellClass(NETTY_HANDLER, GodzillaNettyHandler.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(WEB_FILTER, Suo5WebFilter.class)
                .build());
    }
}
