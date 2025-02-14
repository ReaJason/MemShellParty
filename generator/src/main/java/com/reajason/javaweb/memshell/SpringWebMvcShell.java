package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcControllerHandlerInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcInterceptorInjector;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5ControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5Interceptor;
import org.apache.commons.lang3.tuple.Pair;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringWebMvcShell extends AbstractShell {
    public static final String INTERCEPTOR = "Interceptor";
    public static final String JAKARTA_INTERCEPTOR = "JakartaInterceptor";
    public static final String CONTROLLER_HANDLER = "ControllerHandler";
    public static final String JAKARTA_CONTROLLER_HANDLER = "JakartaControllerHandler";
    public static final String AGENT_FRAMEWORK_SERVLET = "AgentFrameworkServlet";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(JAKARTA_INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(JAKARTA_CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(AGENT_FRAMEWORK_SERVLET, Pair.of(BehinderServletAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(JAKARTA_INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(JAKARTA_CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(AGENT_FRAMEWORK_SERVLET, Pair.of(CommandFilterChainAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(JAKARTA_INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(JAKARTA_CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(AGENT_FRAMEWORK_SERVLET, Pair.of(GodzillaServletAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class));
        return map;
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getSuo5ShellMap() {
        Map<String, Pair<Class<?>, Class<?>>> map = new LinkedHashMap<>();
        map.put(INTERCEPTOR, Pair.of(Suo5Interceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(JAKARTA_INTERCEPTOR, Pair.of(Suo5Interceptor.class, SpringWebMvcInterceptorInjector.class));
        map.put(CONTROLLER_HANDLER, Pair.of(Suo5ControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        map.put(JAKARTA_CONTROLLER_HANDLER, Pair.of(Suo5ControllerHandler.class, SpringWebMvcControllerHandlerInjector.class));
        return map;
    }
}