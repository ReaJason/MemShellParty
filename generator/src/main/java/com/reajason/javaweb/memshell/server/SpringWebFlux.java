package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.springwebflux.SpringWebFluxHandlerFunctionInjector;
import com.reajason.javaweb.memshell.injector.springwebflux.SpringWebFluxHandlerMethodInjector;
import com.reajason.javaweb.memshell.injector.springwebflux.SpringWebFluxNettyHandlerInjector;
import com.reajason.javaweb.memshell.injector.springwebflux.SpringWebFluxWebFilterInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class SpringWebFlux extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SPRING_WEBFLUX_WEB_FILTER, SpringWebFluxWebFilterInjector.class)
                .addInjector(NETTY_HANDLER, SpringWebFluxNettyHandlerInjector.class)
                .addInjector(SPRING_WEBFLUX_HANDLER_METHOD, SpringWebFluxHandlerMethodInjector.class)
                .addInjector(SPRING_WEBFLUX_HANDLER_FUNCTION, SpringWebFluxHandlerFunctionInjector.class)
                .build();
    }
}
