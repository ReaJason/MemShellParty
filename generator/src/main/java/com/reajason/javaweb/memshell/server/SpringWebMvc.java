package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcControllerHandlerInjector;
import com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcFrameworkServletAgentInjector;
import com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcInterceptorInjector;

import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringWebMvc extends AbstractServer {

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