package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.shelltool.command.CommandFilterChainAdvisor;
import com.reajason.javaweb.memshell.springmvc.behinder.BehinderControllerHandler;
import com.reajason.javaweb.memshell.springmvc.behinder.BehinderInterceptor;
import com.reajason.javaweb.memshell.springmvc.behinder.BehinderServletAdvisor;
import com.reajason.javaweb.memshell.springmvc.command.CommandControllerHandler;
import com.reajason.javaweb.memshell.springmvc.command.CommandInterceptor;
import com.reajason.javaweb.memshell.springmvc.godzilla.GodzillaControllerHandler;
import com.reajason.javaweb.memshell.springmvc.godzilla.GodzillaInterceptor;
import com.reajason.javaweb.memshell.springmvc.godzilla.GodzillaServletAdvisor;
import com.reajason.javaweb.memshell.springmvc.injector.SpringControllerHandlerInjector;
import com.reajason.javaweb.memshell.springmvc.injector.SpringFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.springmvc.injector.SpringInterceptorInjector;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringMVCShell extends AbstractShell {
    public static final String INTERCEPTOR = "Interceptor";
    public static final String JAKARTA_INTERCEPTOR = "JakartaInterceptor";
    public static final String CONTROLLER_HANDLER = "ControllerHandler";
    public static final String JAKARTA_CONTROLLER_HANDLER = "JakartaControllerHandler";
    public static final String AGENT_FRAMEWORK_SERVLET = "AgentFrameworkServlet";

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Map.of(
                INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(BehinderInterceptor.class, SpringInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(BehinderControllerHandler.class, SpringControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(BehinderServletAdvisor.class, SpringFrameworkServletAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Map.of(
                INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(CommandInterceptor.class, SpringInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(CommandControllerHandler.class, SpringControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(CommandFilterChainAdvisor.class, SpringFrameworkServletAgentInjector.class)
        );
    }

    @Override
    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Map.of(
                INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringInterceptorInjector.class),
                JAKARTA_INTERCEPTOR, Pair.of(GodzillaInterceptor.class, SpringInterceptorInjector.class),
                CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringControllerHandlerInjector.class),
                JAKARTA_CONTROLLER_HANDLER, Pair.of(GodzillaControllerHandler.class, SpringControllerHandlerInjector.class),
                AGENT_FRAMEWORK_SERVLET, Pair.of(GodzillaServletAdvisor.class, SpringFrameworkServletAgentInjector.class)
        );
    }
}