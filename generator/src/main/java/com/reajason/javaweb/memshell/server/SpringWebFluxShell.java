package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerFunctionInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerMethodInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxNettyHandlerInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxWebFilterInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class SpringWebFluxShell extends AbstractShell {

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SPRING_WEBFLUX_WEB_FILTER, SpringWebFluxWebFilterInjector.class)
                .addInjector(SPRING_WEBFLUX_HANDLER_METHOD, SpringWebFluxHandlerMethodInjector.class)
                .addInjector(SPRING_WEBFLUX_HANDLER_FUNCTION, SpringWebFluxHandlerFunctionInjector.class)
                .addInjector(NETTY_HANDLER, SpringWebFluxNettyHandlerInjector.class)
                .build();
    }
}
