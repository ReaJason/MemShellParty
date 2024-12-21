package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.resin.behinder.BehinderListener;
import com.reajason.javaweb.memshell.resin.command.CommandListener;
import com.reajason.javaweb.memshell.resin.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.resin.injector.ResinFilterInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinListenerInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinServletInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
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
                Constants.SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class),
                Constants.FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class),
                Constants.FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class),
                Constants.FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class),
                Constants.LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class)
        );
    }
}
