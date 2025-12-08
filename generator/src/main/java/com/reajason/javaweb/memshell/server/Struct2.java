package com.reajason.javaweb.memshell.server;

import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.injector.struct2.Struct2ActionInjector;

/**
 * @author ReaJason
 * @since 2025/12/8
 */
public class Struct2 extends AbstractServer {

    @Override
    public InjectorMapping getShellInjectorMapping() {
        return InjectorMapping.builder()
                .addInjector(ShellType.ACTION, Struct2ActionInjector.class)
                .build();
    }
}
