package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcControllerHandlerInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.springwebmvc.injector.SpringWebMvcInterceptorInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringWebMvcShell extends AbstractShell {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SPRING_WEBMVC_INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, SpringWebMvcInterceptorInjector.class)
                .addInjector(SPRING_WEBMVC_CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, SpringWebMvcControllerHandlerInjector.class)
                .addInjector(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, SpringWebMvcFrameworkServletAgentInjector.class)
                .build();
    }
}