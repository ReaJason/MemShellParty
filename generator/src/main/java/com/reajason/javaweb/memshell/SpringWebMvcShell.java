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
import org.apache.commons.lang3.tuple.Pair;

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
        return Map.of(
                INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringWebMvcInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringWebMvcInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(BehinderServletAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringWebMvcInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringWebMvcInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(CommandFilterChainAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringWebMvcInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringWebMvcInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringWebMvcControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(GodzillaServletAdvisor.class, SpringWebMvcFrameworkServletAgentInjector.class)
        );
    }
}