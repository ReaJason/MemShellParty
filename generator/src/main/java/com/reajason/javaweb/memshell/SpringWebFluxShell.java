package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.command.CommandHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.command.CommandWebFilter;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerFunction;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaHandlerMethod;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaWebFilter;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerFunctionInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxHandlerMethodInjector;
import com.reajason.javaweb.memshell.springwebflux.injector.SpringWebFluxWebFilterInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class SpringWebFluxShell extends AbstractShell {
    public static final String WEB_FILTER = "WebFilter";
    public static final String HANDLER_METHOD = "HandlerMethod";
    public static final String HANDLER_FUNCTION = "HandlerFunction";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                WEB_FILTER, Pair.of(CommandWebFilter.class, SpringWebFluxWebFilterInjector.class),
                HANDLER_METHOD, Pair.of(CommandHandlerMethod.class, SpringWebFluxHandlerMethodInjector.class),
                HANDLER_FUNCTION, Pair.of(CommandHandlerFunction.class, SpringWebFluxHandlerFunctionInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                WEB_FILTER, Pair.of(GodzillaWebFilter.class, SpringWebFluxWebFilterInjector.class),
                HANDLER_METHOD, Pair.of(GodzillaHandlerMethod.class, SpringWebFluxHandlerMethodInjector.class),
                HANDLER_FUNCTION, Pair.of(GodzillaHandlerFunction.class, SpringWebFluxHandlerFunctionInjector.class)
        );
    }
}
