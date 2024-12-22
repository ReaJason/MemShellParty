package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.glassfish.behinder.BehinderListener;
import com.reajason.javaweb.memshell.glassfish.command.CommandListener;
import com.reajason.javaweb.memshell.glassfish.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishFilterInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishValveInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFishShell extends AbstractShell {
    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, GlassFishFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(CommandFilter.class, GlassFishFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, GlassFishFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(GodzillaFilter.class, GlassFishFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(BehinderFilter.class, GlassFishFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(BehinderFilter.class, GlassFishFilterInjector.class),
                Constants.LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class)
        );
    }
}
