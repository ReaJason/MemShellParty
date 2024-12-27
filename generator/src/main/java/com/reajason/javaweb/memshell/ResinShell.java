package com.reajason.javaweb.memshell;

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

import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class ResinShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class),
                JAKARTA_SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class),
                JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class),
                JAKARTA_SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class),
                JAKARTA_FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class)
        );
    }
}
