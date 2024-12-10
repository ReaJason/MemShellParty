package com.reajason.javaweb.memsell.jboss;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.jboss.command.CommandFilter;
import com.reajason.javaweb.memsell.jboss.command.CommandListener;
import com.reajason.javaweb.memsell.jboss.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.jboss.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.jboss.injector.JbossFilterInjector;
import com.reajason.javaweb.memsell.jboss.injector.JbossListenerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JbossShell extends AbstractShell {

    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Command, ShellTool.Godzilla);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, JbossFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, JbossListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, JbossFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, JbossListenerInjector.class)
        );
    }
}