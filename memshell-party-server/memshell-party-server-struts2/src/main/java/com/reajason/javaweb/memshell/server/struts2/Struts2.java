package com.reajason.javaweb.memshell.server.struts2;

import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.memshell.server.InjectorMapping;

import com.reajason.javaweb.memshell.ShellType;

/**
 * @author ReaJason
 * @since 2025/12/8
 */
public class Struts2 extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.ACTION, "com.reajason.javaweb.memshell.injector.struts2.Struts2ActionInjector")
                .build();
    }
}
