package com.reajason.javaweb.memshell.shelltool.wsproxy;

import com.reajason.javaweb.memshell.generator.ByteBuddyShellGenerator;

import com.reajason.javaweb.memshell.config.ShellConfig;
import net.bytebuddy.dynamic.DynamicType;

public class ProxyGenerator extends ByteBuddyShellGenerator<ProxyConfig> {
    public ProxyGenerator(ShellConfig shellConfig, ProxyConfig shellToolConfig) {
        super(shellConfig, shellToolConfig);
    }

    @Override
    protected DynamicType.Builder<?> getBuilder() {
        return redefineTemplate();
    }
}
