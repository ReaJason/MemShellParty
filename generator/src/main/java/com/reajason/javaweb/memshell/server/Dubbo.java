package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.injector.dubbo.AlibabaDubboServiceInjector;
import com.reajason.javaweb.memshell.injector.dubbo.ApacheDubboServiceInjector;

public class Dubbo extends AbstractServer {
    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.APACHE_DUBBO_SERVICE, ApacheDubboServiceInjector.class)
                .addInjector(ShellType.ALIBABA_DUBBO_SERVICE, AlibabaDubboServiceInjector.class)
                .build();
    }
}
