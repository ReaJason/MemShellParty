package com.reajason.javaweb.memshell.server.resin2;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;


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
                .addInjector(FILTER, "com.reajason.javaweb.memshell.injector.resin2.Resin2FilterInjector")
                .addInjector(SERVLET, "com.reajason.javaweb.memshell.injector.resin2.Resin2ServletInjector")
                .build();
    }
}
