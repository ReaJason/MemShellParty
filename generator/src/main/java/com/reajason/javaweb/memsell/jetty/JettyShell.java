package com.reajason.javaweb.memsell.jetty;

import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.jetty.command.CommandFilter;
import com.reajason.javaweb.memsell.jetty.command.CommandListener;
import com.reajason.javaweb.memsell.jetty.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.jetty.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.jetty.injector.JettyFilterInjector;
import com.reajason.javaweb.memsell.jetty.injector.JettyListenerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

import static com.reajason.javaweb.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class JettyShell extends AbstractShell {

    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Godzilla, ShellTool.Command);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class)
        );
    }
}
