package com.reajason.javaweb.memshell.server.springwebmvc;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;


import static com.reajason.javaweb.memshell.ShellType.*;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
public class SpringWebMvc extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SPRING_WEBMVC_INTERCEPTOR, "com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcInterceptorInjector")
                .addInjector(SPRING_WEBMVC_JAKARTA_INTERCEPTOR, "com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcInterceptorInjector")
                .addInjector(SPRING_WEBMVC_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcControllerHandlerInjector")
                .addInjector(SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, "com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcControllerHandlerInjector")
                .addInjector(SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET, "com.reajason.javaweb.memshell.injector.springwebmvc.SpringWebMvcFrameworkServletAgentInjector")
                .build();
    }
}
