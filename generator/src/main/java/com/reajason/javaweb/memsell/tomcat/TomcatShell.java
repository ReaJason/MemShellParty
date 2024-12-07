package com.reajason.javaweb.memsell.tomcat;

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
    protected void initializeShellMaps() {
        godzillaShellMap.put(FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class));
        godzillaShellMap.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class));
        godzillaShellMap.put(LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class));
        godzillaShellMap.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class));
        godzillaShellMap.put(VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class));
        godzillaShellMap.put(JAKARTA_VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class));

        commandShellMap.put(FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class));
        commandShellMap.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class));
        commandShellMap.put(LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class));
        commandShellMap.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class));
        commandShellMap.put(VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class));
        commandShellMap.put(JAKARTA_VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class));
    }
}