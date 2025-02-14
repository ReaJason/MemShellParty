package com.reajason.javaweb.memshell;

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
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

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
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(WEB_FILTER, Pair.of(CommandWebFilter.class, SpringWebFluxWebFilterInjector.class));
        map.put(HANDLER_METHOD, Pair.of(CommandHandlerMethod.class, SpringWebFluxHandlerMethodInjector.class));
        map.put(HANDLER_FUNCTION, Pair.of(CommandHandlerFunction.class, SpringWebFluxHandlerFunctionInjector.class));
        map.put(NETTY_HANDLER, Pair.of(CommandNettyHandler.class, SpringWebFluxNettyHandlerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(WEB_FILTER, Pair.of(GodzillaWebFilter.class, SpringWebFluxWebFilterInjector.class));
        map.put(HANDLER_METHOD, Pair.of(GodzillaHandlerMethod.class, SpringWebFluxHandlerMethodInjector.class));
        map.put(HANDLER_FUNCTION, Pair.of(GodzillaHandlerFunction.class, SpringWebFluxHandlerFunctionInjector.class));
        map.put(NETTY_HANDLER, Pair.of(GodzillaNettyHandler.class, SpringWebFluxNettyHandlerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(WEB_FILTER, Pair.of(Suo5WebFilter.class, SpringWebFluxWebFilterInjector.class));
        return map;
    }
}
