package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.jetty.behinder.BehinderHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.behinder.BehinderListener;
import com.reajason.javaweb.memshell.jetty.command.CommandHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.command.CommandListener;
import com.reajason.javaweb.memshell.jetty.godzilla.GodzillaHandlerAdvisor;
import com.reajason.javaweb.memshell.jetty.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.jetty.injector.JettyFilterInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyHandlerAgentInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyListenerInjector;
import com.reajason.javaweb.memshell.jetty.injector.JettyServletInjector;
import com.reajason.javaweb.memshell.jetty.suo5.Suo5Listener;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderFilter;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderServlet;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandServlet;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaServlet;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Filter;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Servlet;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

import static com.reajason.javaweb.memshell.config.Constants.*;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public class JettyShell extends AbstractShell {
    public static final String AGENT_HANDLER = AGENT + "Handler";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(CommandServlet.class, JettyServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(CommandServlet.class, JettyServletInjector.class));
        map.put(FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(CommandFilter.class, JettyFilterInjector.class));
        map.put(LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(CommandListener.class, JettyListenerInjector.class));
        map.put(AGENT_HANDLER, Pair.of(CommandHandlerAdvisor.class, JettyHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(GodzillaServlet.class, JettyServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(GodzillaServlet.class, JettyServletInjector.class));
        map.put(FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(GodzillaFilter.class, JettyFilterInjector.class));
        map.put(LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(GodzillaListener.class, JettyListenerInjector.class));
        map.put(AGENT_HANDLER, Pair.of(GodzillaHandlerAdvisor.class, JettyHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(BehinderServlet.class, JettyServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(BehinderServlet.class, JettyServletInjector.class));
        map.put(FILTER, Pair.of(BehinderFilter.class, JettyFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(BehinderFilter.class, JettyFilterInjector.class));
        map.put(LISTENER, Pair.of(BehinderListener.class, JettyListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(BehinderListener.class, JettyListenerInjector.class));
        map.put(AGENT_HANDLER, Pair.of(BehinderHandlerAdvisor.class, JettyHandlerAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(SERVLET, Pair.of(Suo5Servlet.class, JettyServletInjector.class));
        map.put(JAKARTA_SERVLET, Pair.of(Suo5Servlet.class, JettyServletInjector.class));
        map.put(FILTER, Pair.of(Suo5Filter.class, JettyFilterInjector.class));
        map.put(JAKARTA_FILTER, Pair.of(Suo5Filter.class, JettyFilterInjector.class));
        map.put(LISTENER, Pair.of(Suo5Listener.class, JettyListenerInjector.class));
        map.put(JAKARTA_LISTENER, Pair.of(Suo5Listener.class, JettyListenerInjector.class));
        return map;
    }
}
