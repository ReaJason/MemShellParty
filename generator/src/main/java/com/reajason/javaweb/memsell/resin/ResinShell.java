package com.reajason.javaweb.memsell.resin;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.resin.command.CommandFilter;
import com.reajason.javaweb.memsell.resin.command.CommandListener;
import com.reajason.javaweb.memsell.resin.godzilla.GodzillaFilter;
import com.reajason.javaweb.memsell.resin.godzilla.GodzillaListener;
import com.reajason.javaweb.memsell.resin.injector.ResinFilterInjector;
import com.reajason.javaweb.memsell.resin.injector.ResinListenerInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class ResinShell extends AbstractShell {
    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Godzilla, ShellTool.Command);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class)
        );
    }
}
