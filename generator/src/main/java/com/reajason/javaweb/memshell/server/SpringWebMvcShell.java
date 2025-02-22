package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.antsword.AntSwordServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.behinder.BehinderServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.command.CommandServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaInterceptor;
import com.reajason.javaweb.memshell.springwebmvc.godzilla.GodzillaServletAdvisor;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcControllerHandlerInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcInterceptorInjector;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5ControllerHandler;
import com.reajason.javaweb.memshell.springwebmvc.suo5.Suo5Interceptor;

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
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(JAKARTA_INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(JAKARTA_CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(AGENT_FRAMEWORK_SERVLET, SpringWebMvcFrameworkServletAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(JAKARTA_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(JAKARTA_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(AGENT_FRAMEWORK_SERVLET, CommandServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(JAKARTA_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(JAKARTA_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(AGENT_FRAMEWORK_SERVLET, GodzillaServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(JAKARTA_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(JAKARTA_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(AGENT_FRAMEWORK_SERVLET, BehinderServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(JAKARTA_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(JAKARTA_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(JAKARTA_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(JAKARTA_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(AGENT_FRAMEWORK_SERVLET, AntSwordServletAdvisor.class)
                .build());
    }
}