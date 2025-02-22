package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
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

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.SPRING_WEBFLUX_WEB_FILTER, SpringWebFluxWebFilterInjector.class)
                .addInjector(ShellType.SPRING_WEBFLUX_HANDLER_METHOD, SpringWebFluxHandlerMethodInjector.class)
                .addInjector(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION, SpringWebFluxHandlerFunctionInjector.class)
                .addInjector(ShellType.NETTY_HANDLER, SpringWebFluxNettyHandlerInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBFLUX_WEB_FILTER, CommandWebFilter.class)
                .addShellClass(ShellType.SPRING_WEBFLUX_HANDLER_METHOD, CommandHandlerMethod.class)
                .addShellClass(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION, CommandHandlerFunction.class)
                .addShellClass(ShellType.NETTY_HANDLER, CommandNettyHandler.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBFLUX_WEB_FILTER, GodzillaWebFilter.class)
                .addShellClass(ShellType.SPRING_WEBFLUX_HANDLER_METHOD, GodzillaHandlerMethod.class)
                .addShellClass(ShellType.SPRING_WEBFLUX_HANDLER_FUNCTION, GodzillaHandlerFunction.class)
                .addShellClass(ShellType.NETTY_HANDLER, GodzillaNettyHandler.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBFLUX_WEB_FILTER, Suo5WebFilter.class)
                .build());
    }
}
