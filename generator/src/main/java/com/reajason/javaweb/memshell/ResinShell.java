package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.resin.behinder.BehinderListener;
import com.reajason.javaweb.memshell.resin.command.CommandListener;
import com.reajason.javaweb.memshell.resin.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.resin.injector.ResinFilterChainAgentInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinFilterInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinListenerInjector;
import com.reajason.javaweb.memshell.resin.injector.ResinServletInjector;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilterChainAdvisor;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import org.apache.commons.lang3.tuple.Pair;

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
        return Map.of(
                SERVLET, Pair.of(CommandServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(CommandFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, ResinListenerInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, ResinFilterChainAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                SERVLET, Pair.of(GodzillaServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(GodzillaFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, ResinListenerInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, ResinFilterChainAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                SERVLET, Pair.of(BehinderServlet.class, ResinServletInjector.class),
                FILTER, Pair.of(BehinderFilter.class, ResinFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, ResinListenerInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, ResinFilterChainAgentInjector.class)
        );
    }
}
