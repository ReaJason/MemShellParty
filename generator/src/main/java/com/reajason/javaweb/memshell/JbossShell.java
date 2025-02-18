package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.jboss.injector.JbossFilterInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossListenerInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossValveInjector;
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
import com.reajason.javaweb.memshell.tomcat.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.tomcat.suo5.Suo5Listener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JbossShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(CommandFilter.class, JbossFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, JbossListenerInjector.class));
        map.put(VALVE, Pair.of(CommandValve.class, JbossValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(GodzillaFilter.class, JbossFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, JbossListenerInjector.class));
        map.put(VALVE, Pair.of(GodzillaValve.class, JbossValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(BehinderFilter.class, JbossFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, JbossListenerInjector.class));
        map.put(VALVE, Pair.of(BehinderValve.class, JbossValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(Suo5Filter.class, JbossFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, JbossListenerInjector.class));
        map.put(VALVE, Pair.of(Suo5Valve.class, JbossValveInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getAntSwordShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(FILTER, Pair.of(AntSwordFilter.class, JbossFilterInjector.class));
        map.put(LISTENER, Pair.of(AntSwordListener.class, JbossListenerInjector.class));
        map.put(VALVE, Pair.of(AntSwordValve.class, JbossValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(AntSwordFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(AntSwordFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }
}