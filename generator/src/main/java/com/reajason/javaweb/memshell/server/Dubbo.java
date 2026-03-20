package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.injector.dubbo.DubboServiceInjector;

public class Dubbo extends AbstractServer {
    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.DUBBO_SERVICE, DubboServiceInjector.class)
                .build();
    }
}
