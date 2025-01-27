package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.springwebflux.command.CommandNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaNettyHandler;
import com.reajason.javaweb.memshell.xxljob.injector.XxlJobNettyHandlerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobShell extends AbstractShell {
    public static final String NETTY_HANDLER = "NettyHandler";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(NETTY_HANDLER, Pair.of(CommandNettyHandler.class, XxlJobNettyHandlerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(NETTY_HANDLER, Pair.of(GodzillaNettyHandler.class, XxlJobNettyHandlerInjector.class));
        return map;
    }
}
