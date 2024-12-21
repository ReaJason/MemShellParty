package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.payara.behinder.BehinderListener;
import com.reajason.javaweb.memshell.payara.command.CommandListener;
import com.reajason.javaweb.memshell.payara.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.payara.injector.PayaraFilterInjector;
import com.reajason.javaweb.memshell.payara.injector.PayaraListenerInjector;
import com.reajason.javaweb.memshell.payara.injector.PayaraValveInjector;
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

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(BehinderFilter.class, PayaraFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(BehinderFilter.class, PayaraFilterInjector.class),
                Constants.LISTENER, Pair.of(BehinderListener.class, PayaraListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(BehinderListener.class, PayaraListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, PayaraValveInjector.class),
                JAKARTA_VALVE, Pair.of(BehinderValve.class, PayaraValveInjector.class)
        );
    }
}
