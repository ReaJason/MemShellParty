package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.glassfish.injector.GlassFishListenerInjector;
import com.reajason.javaweb.memshell.glassfish.injector.GlassFishValveInjector;
import com.reajason.javaweb.memshell.inforsuite.injector.InforSuiteFilterInjector;
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
 * @since 2024/12/24
 */
public class InforSuiteShell extends AbstractShell {

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                FILTER, Pair.of(CommandFilter.class, InforSuiteFilterInjector.class),
                JAKARTA_FILTER, Pair.of(CommandFilter.class, InforSuiteFilterInjector.class),
                LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(CommandListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(CommandValve.class, GlassFishValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(CommandFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(CommandFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                FILTER, Pair.of(GodzillaFilter.class, InforSuiteFilterInjector.class),
                JAKARTA_FILTER, Pair.of(GodzillaFilter.class, InforSuiteFilterInjector.class),
                LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(GodzillaListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(GodzillaValve.class, GlassFishValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(GodzillaFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(GodzillaFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                FILTER, Pair.of(BehinderFilter.class, InforSuiteFilterInjector.class),
                JAKARTA_FILTER, Pair.of(BehinderFilter.class, InforSuiteFilterInjector.class),
                LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class),
                JAKARTA_LISTENER, Pair.of(BehinderListener.class, GlassFishListenerInjector.class),
                VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class),
                JAKARTA_VALVE, Pair.of(BehinderValve.class, GlassFishValveInjector.class),
                AGENT_FILTER_CHAIN, Pair.of(BehinderFilterChainAdvisor.class, TomcatFilterChainAgentInjector.class),
                AGENT_CONTEXT_VALVE, Pair.of(BehinderFilterChainAdvisor.class, TomcatContextValveAgentInjector.class)
        );
    }
}
