package com.reajason.javaweb.memsell.undertow;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.undertow.command.CommandFilter;
import com.reajason.javaweb.memsell.undertow.command.CommandListener;
import com.reajason.javaweb.memsell.undertow.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.undertow.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.undertow.injector.UndertowFilterInjector;
import com.reajason.javaweb.memsell.undertow.injector.UndertowListenerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {
    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Command, ShellTool.Godzilla);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class)
        );
    }
}
