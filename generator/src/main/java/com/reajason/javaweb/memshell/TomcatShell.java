package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Valve;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandWebSocket;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.tomcat.injector.*;
import com.reajason.javaweb.memshell.tomcat.suo5.Suo5Listener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public class TomcatShell extends AbstractShell {
    public static final String WEBSOCKET = "WebSocket";
    public static final String UPGRADE = "Upgrade";
    public static final String EXECUTOR = "Executor";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class));
        map.put(VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        map.put(WEBSOCKET, Pair.of(CommandWebSocket.class, TomcatWebSocketInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class));
        map.put(VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, TomcatServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(BehinderServlet.class, TomcatServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, TomcatFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(BehinderFilter.class, TomcatFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, TomcatListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(BehinderListener.class, TomcatListenerInjector.class));
        map.put(VALVE, Pair.of(BehinderValve.class, TomcatValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(BehinderValve.class, TomcatValveInjector.class));
        map.put(AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class));
        map.put(AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TomcatContextValveAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(Suo5Servlet.class, TomcatServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(Suo5Servlet.class, TomcatServletInjector.class));
        map.put(FILTER, Pair.of(Suo5Filter.class, TomcatFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(Suo5Filter.class, TomcatFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, TomcatListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(Suo5Listener.class, TomcatListenerInjector.class));
        map.put(VALVE, Pair.of(Suo5Valve.class, TomcatValveInjector.class));
        map.put(JAKARTA_VALVE, Pair.of(Suo5Valve.class, TomcatValveInjector.class));
        return map;
    }
}