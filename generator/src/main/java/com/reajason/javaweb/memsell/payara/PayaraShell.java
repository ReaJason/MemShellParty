package com.reajason.javaweb.memsell.payara;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.payara.command.CommandFilter;
import com.reajason.javaweb.memsell.payara.command.CommandListener;
import com.reajason.javaweb.memsell.payara.command.CommandValve;
import com.reajason.javaweb.memsell.payara.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.payara.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.payara.godzilla.GodzillaValve;
import com.reajason.javaweb.memsell.payara.injector.PayaraFilterInjector;
import com.reajason.javaweb.memsell.payara.injector.PayaraListenerInjector;
import com.reajason.javaweb.memsell.payara.injector.PayaraValveInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class PayaraShell extends AbstractShell {
    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";

    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Command, ShellTool.Godzilla);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, PayaraFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(CommandFilter.class, PayaraFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, PayaraListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(CommandListener.class, PayaraListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, PayaraValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve.class, PayaraValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, PayaraFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(GodzillaFilter.class, PayaraFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, PayaraListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(GodzillaListener.class, PayaraListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, PayaraValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, PayaraValveInjector.class)
        );
    }
}
