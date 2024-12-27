package com.reajason.javaweb.memshell;

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

import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class),
                JAKARTA_SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class),
                FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class),
                JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class),
                JAKARTA_SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class),
                FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class),
                JAKARTA_FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class)
        );
    }
}
