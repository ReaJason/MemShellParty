package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.ShellGenerator;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;
import org.apache.commons.lang3.tuple.Pair;

import java.lang.reflect.Constructor;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * @author ReaJason
 * @since 2025/08/22
 */
public class ShellToolFactory {
    private static final Map<String, Pair<Class<? extends ShellGenerator>, Class<? extends ShellToolConfig>>> instances = new ConcurrentHashMap<>();

    static {
        register(ShellTool.Godzilla, GodzillaGenerator.class, GodzillaConfig.class);
        register(ShellTool.Behinder, BehinderGenerator.class, BehinderConfig.class);
        register(ShellTool.Command, CommandGenerator.class, CommandConfig.class);
        register(ShellTool.Suo5, Suo5Generator.class, Suo5Config.class);
        register(ShellTool.Suo5v2, Suo5Generator.class, Suo5Config.class);
        register(ShellTool.AntSword, AntSwordGenerator.class, AntSwordConfig.class);
        register(ShellTool.NeoreGeorg, NeoreGeorgGenerator.class, NeoreGeorgConfig.class);
        register(ShellTool.Custom, CustomShellGenerator.class, CustomConfig.class);
        register(ShellTool.Proxy, ProxyGenerator.class, ProxyConfig.class);
    }

    public static void register(String shellToolName, Class<? extends ShellGenerator> generatorClass, Class<? extends ShellToolConfig> configClass) {
        if (shellToolName == null || shellToolName.trim().isEmpty()) {
            throw new IllegalArgumentException("ShellTool name cannot be null or empty.");
        }
        instances.put(shellToolName, Pair.of(generatorClass, configClass));
    }


    public static byte[] generateBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        try {
            Pair<Class<? extends ShellGenerator>, Class<? extends ShellToolConfig>> classClassPair = instances.get(shellConfig.getShellTool());
            Constructor<? extends ShellGenerator> constructor =
                    classClassPair.getLeft().getConstructor(ShellConfig.class, classClassPair.getRight());
            ShellGenerator generator = constructor.newInstance(shellConfig, classClassPair.getRight().cast(shellToolConfig));
            return generator.getBytes();
        } catch (Exception e) {
            throw new GenerationException("shell generate failed " + e.getMessage(), e);
        }
    }
}
