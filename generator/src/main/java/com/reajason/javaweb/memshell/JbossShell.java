package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.jboss.injector.JbossFilterInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossListenerInjector;
import com.reajason.javaweb.memshell.jboss.injector.JbossValveInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatContextValveAgentInjector;
import com.reajason.javaweb.memshell.tomcat.injector.TomcatFilterChainAgentInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class JbossShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                FILTER, Pair.of(CommandFilter.class, JbossFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, JbossListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, JbossValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                FILTER, Pair.of(GodzillaFilter.class, JbossFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, JbossListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, JbossValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                FILTER, Pair.of(BehinderFilter.class, JbossFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, JbossListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, JbossValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }
}