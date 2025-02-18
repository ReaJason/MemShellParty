package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.resin.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.resin.behinder.BehinderListener;
import com.reajason.javaweb.memshell.resin.command.CommandListener;
import com.reajason.javaweb.memshell.resin.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.resin.injector.ResinFilterChainAgentInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinFilterInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinListenerInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinServletInjector;
import com.reajason.javaweb.memshell.resin.suo5.Suo5Listener;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilter;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.antsword.AntSwordServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/14
 */
public class ResinShell extends AbstractShell {
    public static final String AGENT_FILTER_CHAIN = AGENT + "FilterChain";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, ResinFilterChainAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, ResinFilterChainAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, ResinFilterChainAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(Suo5Servlet.class, ResinServletInjector.class));
        map.put(FILTER, Pair.of(Suo5Filter.class, ResinFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, ResinListenerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getAntSwordShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(AntSwordServlet.class, ResinServletInjector.class));
        map.put(FILTER, Pair.of(AntSwordFilter.class, ResinFilterInjector.class));
        map.put(LISTENER, Pair.of(AntSwordListener.class, ResinListenerInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(AntSwordFilterChainAdvisor.class, ResinFilterChainAgentInjector.class));
        return map;
    }
}
