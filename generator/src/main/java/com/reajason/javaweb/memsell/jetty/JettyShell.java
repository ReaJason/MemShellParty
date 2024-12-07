package com.reajason.javaweb.memsell.jetty;

import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.jetty.command.CommandFilter;
import com.reajason.javaweb.memsell.jetty.command.CommandListener;
import com.reajason.javaweb.memsell.jetty.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.jetty.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.jetty.injector.JettyFilterInjector;
import com.reajason.javaweb.memsell.jetty.injector.JettyListenerInjector;
import org.apache.commons.lang3.tuple.Pair;

import static com.reajason.javaweb.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class JettyShell extends AbstractShell {

    @Override
    protected void initializeShellMaps() {
        godzillaShellMap.put(FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class));
        godzillaShellMap.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class));
        godzillaShellMap.put(LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class));
        godzillaShellMap.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class));

        commandShellMap.put(FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class));
        commandShellMap.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class));
        commandShellMap.put(LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class));
        commandShellMap.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class));
    }
}
