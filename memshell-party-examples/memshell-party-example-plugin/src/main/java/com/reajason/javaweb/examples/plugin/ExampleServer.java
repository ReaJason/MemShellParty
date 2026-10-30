package com.reajason.javaweb.examples.plugin;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

public class ExampleServer extends AbstractServer {
    static final String SHELL_TYPE = "Example";

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(SHELL_TYPE, ExampleInjector.class.getName())
                .build();
    }
}
