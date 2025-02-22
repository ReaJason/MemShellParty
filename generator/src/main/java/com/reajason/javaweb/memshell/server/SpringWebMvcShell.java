package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
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

    @Override
    protected InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.SPRING_WEBMVC_INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, SpringWebMvcFrameworkServletAgentInjector.class)
                .build();
    }

    @Override
    protected void init() {
        addToolMapping(ShellTool.Command, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBMVC_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, CommandInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, CommandControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, CommandServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Godzilla, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBMVC_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, GodzillaInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, GodzillaControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, GodzillaServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Behinder, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBMVC_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, BehinderInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, BehinderControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, BehinderServletAdvisor.class)
                .build());

        addToolMapping(ShellTool.Suo5, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBMVC_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, Suo5Interceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, Suo5ControllerHandler.class)
                .build());

        addToolMapping(ShellTool.AntSword, ToolMapping.builder()
                .addShellClass(ShellType.SPRING_WEBMVC_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, AntSwordInterceptor.class)
                .addShellClass(ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, AntSwordControllerHandler.class)
                .addShellClass(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, AntSwordServletAdvisor.class)
                .build());
    }
}