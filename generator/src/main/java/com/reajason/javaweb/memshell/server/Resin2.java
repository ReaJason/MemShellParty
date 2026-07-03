package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.injector.resin2.Resin2FilterInjector;
import com.reajason.javaweb.memshell.injector.resin2.Resin2ServletInjector;

import static com.reajason.javaweb.memshell.ShellType.FILTER;
import static com.reajason.javaweb.memshell.ShellType.SERVLET;

/**
 * @author ReaJason
 * @since 2026/7/4
 */
public class Resin2 extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(FILTER, Resin2FilterInjector.class)
                .addInjector(SERVLET, Resin2ServletInjector.class)
                .build();
    }
}
