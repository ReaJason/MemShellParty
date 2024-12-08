package com.reajason.javaweb.memsell.tomcat;

import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.tomcat.command.CommandFilter;
import com.reajason.javaweb.memsell.tomcat.command.CommandListener;
import com.reajason.javaweb.memsell.tomcat.command.CommandValve;
import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.tomcat.godzilla.GodzillaValve;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatFilterInjector;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatListenerInjector;
import com.reajason.javaweb.memsell.tomcat.injector.TomcatValveInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

import static com.reajason.javaweb.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell extends AbstractShell {
    public static final String WEBSOCKET = "Websocket";
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
                FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class)
        );
    }
}