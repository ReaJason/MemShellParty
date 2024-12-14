package com.reajason.javaweb.memsell.glassfish;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.glassfish.command.CommandFilter;
import com.reajason.javaweb.memsell.glassfish.command.CommandListener;
import com.reajason.javaweb.memsell.glassfish.command.CommandValve;
import com.reajason.javaweb.memsell.glassfish.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.glassfish.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.glassfish.godzilla.GodzillaValve;
import com.reajason.javaweb.memsell.glassfish.injector.GlassFishFilterInjector;
import com.reajason.javaweb.memsell.glassfish.injector.GlassFishListenerInjector;
import com.reajason.javaweb.memsell.glassfish.injector.GlassFishValveInjector;
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
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Command, ShellTool.Godzilla);
    }

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
}
