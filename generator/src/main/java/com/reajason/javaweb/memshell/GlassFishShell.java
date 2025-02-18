package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.glassfish.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.glassfish.behinder.BehinderListener;
import com.reajason.javaweb.memshell.glassfish.command.CommandListener;
import com.reajason.javaweb.memshell.glassfish.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishFilterInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishValveInjector;
import com.reajason.javaweb.memshell.glassfish.suo5.Suo5Listener;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordValve;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatFilterChainAgentInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
public class GlassFishShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(CommandFilter.class, GlassFishFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, GlassFishFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class));
        map.put(VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(GodzillaFilter.class, GlassFishFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, GlassFishFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class));
        map.put(VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(BehinderFilter.class, GlassFishFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(BehinderFilter.class, GlassFishFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class));
        map.put(VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(Suo5Filter.class, GlassFishFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(Suo5Filter.class, GlassFishFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, GlassFishListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(Suo5Listener.class, GlassFishListenerInjector.class));
        map.put(VALVE, Pair.of(Suo5Valve.class, GlassFishValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(Suo5Valve.class, GlassFishValveInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getAntSwordShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(AntSwordFilter.class, GlassFishFilterInjector.class));
        map.put(LISTENER, Pair.of(AntSwordListener.class, GlassFishListenerInjector.class));
        map.put(VALVE, Pair.of(AntSwordValve.class, GlassFishValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(AntSwordFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(AntSwordFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }
}