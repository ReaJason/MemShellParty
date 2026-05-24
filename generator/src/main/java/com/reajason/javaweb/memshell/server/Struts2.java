package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.injector.struts2.Struts2ActionInjector;

/**
 * @author ReaJason
 * @since 2025/12/8
 */
public class Struts2 extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.ACTION, Struts2ActionInjector.class)
                .build();
    }
}
