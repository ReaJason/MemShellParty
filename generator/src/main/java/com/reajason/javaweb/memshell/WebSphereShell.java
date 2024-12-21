package com.reajason.javaweb.memshell;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.websphere.command.CommandListener;
import com.reajason.javaweb.memshell.websphere.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereFilterInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereListenerInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereServletInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class WebSphereShell extends AbstractShell {
    @Override
    public List<ShellTool> getSupportedShellTools() {
        return List.of(ShellTool.Command, ShellTool.Godzilla);
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(CommandServlet.class, WebSphereServletInjector.class),
                Constants.FILTER, Pair.of(CommandFilter.class, WebSphereFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, WebSphereListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(GodzillaServlet.class, WebSphereServletInjector.class),
                Constants.FILTER, Pair.of(GodzillaFilter.class, WebSphereFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, WebSphereListenerInjector.class)
        );
    }
}
