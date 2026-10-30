package com.reajason.javaweb.examples.plugin;

import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.server.ToolMapping;
import com.reajason.javaweb.memshell.spi.ShellToolMeta;
import com.reajason.javaweb.memshell.spi.ShellToolProvider;
import org.kohsuke.MetaInfServices;

@MetaInfServices(ShellToolProvider.class)
@ShellToolMeta(name = ExampleShellToolProvider.NAME, order = 1000)
public class ExampleShellToolProvider implements ShellToolProvider {
    public static final String NAME = "ExamplePluginTool";

    @Override
    public ToolMapping getToolMapping() {
        return ToolMapping.builder()
                .addShellClass(ExampleServer.SHELL_TYPE, ExampleShell.class.getName())
                .build();
    }

    @Override
    public Class<? extends ShellToolConfig> getConfigClass() {
        return ExampleShellToolConfig.class;
    }

    @Override
    public Class<? extends ShellGenerator> getGeneratorClass() {
        return ExampleShellGenerator.class;
    }
}
