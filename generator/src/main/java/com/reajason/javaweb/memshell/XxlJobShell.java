package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.springwebflux.command.CommandNettyHandler;
import com.reajason.javaweb.memshell.springwebflux.godzilla.GodzillaNettyHandler;
import com.reajason.javaweb.memshell.xxljob.injector.XxlJobNettyHandlerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2025/1/21
 */
public class XxlJobShell extends AbstractShell {
    public static final String NETTY_HANDLER = "NettyHandler";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                NETTY_HANDLER, Pair.of(CommandNettyHandler.class, XxlJobNettyHandlerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                NETTY_HANDLER, Pair.of(GodzillaNettyHandler.class, XxlJobNettyHandlerInjector.class)
        );
    }
}
