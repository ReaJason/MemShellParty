package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.websphere.behinder.BehinderListener;
import com.reajason.javaweb.memshell.websphere.command.CommandListener;
import com.reajason.javaweb.memshell.websphere.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereFilterChainAgentInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereFilterInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereListenerInjector;
import com.reajason.javaweb.memshell.websphere.injector.WebSphereServletInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
public class WebSphereShell extends AbstractShell {
    public static final String AGENT_FILTER_MANAGER = AGENT + "FilterManager";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, WebSphereServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, WebSphereFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, WebSphereListenerInjector.class));
        map.put(AGENT_FILTER_MANAGER, Pair.of(CommandFilterChainAdvisor.class, WebSphereFilterChainAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, WebSphereServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, WebSphereFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, WebSphereListenerInjector.class));
        map.put(AGENT_FILTER_MANAGER, Pair.of(GodzillaFilterChainAdvisor.class, WebSphereFilterChainAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, WebSphereServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, WebSphereFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, WebSphereListenerInjector.class));
        map.put(AGENT_FILTER_MANAGER, Pair.of(BehinderFilterChainAdvisor.class, WebSphereFilterChainAgentInjector.class));
        return map;
    }
}
