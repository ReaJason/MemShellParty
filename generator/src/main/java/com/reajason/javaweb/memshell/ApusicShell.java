package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.apusic.behinder.BehinderListener;
import com.reajason.javaweb.memshell.apusic.command.CommandListener;
import com.reajason.javaweb.memshell.apusic.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.apusic.injector.ApusicFilterInjector;
import com.reajason.javaweb.memshell.apusic.injector.ApusicListenerInjector;
import com.reajason.javaweb.memshell.apusic.injector.ApusicServletInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/27
 */
public class ApusicShell extends AbstractShell {
    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, ApusicServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, ApusicFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, ApusicListenerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, ApusicServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, ApusicFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, ApusicListenerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, ApusicServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, ApusicFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, ApusicListenerInjector.class));
        return map;
    }
}
