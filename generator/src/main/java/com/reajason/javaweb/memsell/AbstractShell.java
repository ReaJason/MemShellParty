package com.reajason.javaweb.memsell;

import com.reajason.javaweb.config.*;
import org.apache.commons.lang3.tuple.Pair;

import java.util.HashMap;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public abstract class AbstractShell {
    protected final Map<String, Pair<Class<?>, Class<?>>> godzillaShellMap = new HashMap<>();
    protected final Map<String, Pair<Class<?>, Class<?>>> commandShellMap = new HashMap<>();

    public AbstractShell() {
        initializeShellMaps();
    }

    /**
     * setup map
     */
    protected abstract void initializeShellMaps();

    public GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        Class<?> injectorClass = injectorConfig.getInjectorClass();
        byte[] shellBytes;

        Pair<Class<?>, Class<?>> classPair = getClassPair(shellConfig);

        if (injectorClass == null) {
            injectorClass = classPair.getRight();
        }
        shellToolConfig.setClazz(classPair.getLeft());

        shellBytes = generateShellBytes(shellConfig, shellToolConfig);

        injectorConfig = injectorConfig
                .toBuilder()
                .injectorClass(injectorClass)
                .shellClassName(shellToolConfig.getClassName())
                .shellClassBytes(shellBytes).build();

        byte[] injectorBytes = InjectorGenerator.generate(shellConfig, injectorConfig);

        return GenerateResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getClassName())
                .shellBytes(shellBytes)
                .injectorClassName(injectorClass.getName())
                .injectorBytes(injectorBytes)
                .build();
    }

    private Pair<Class<?>, Class<?>> getClassPair(ShellConfig shellConfig) {
        Map<String, Pair<Class<?>, Class<?>>> shellMap = shellConfig.getShellTool() == ShellTool.Godzilla ? godzillaShellMap : commandShellMap;
        return shellMap.get(shellConfig.getShellType());
    }

    private byte[] generateShellBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        return switch (shellConfig.getShellTool()) {
            case Godzilla -> GodzillaGenerator.generate(shellConfig, (GodzillaConfig) shellToolConfig);
            case Command -> CommandGenerator.generate(shellConfig, (CommandConfig) shellToolConfig);
            default -> throw new UnsupportedOperationException("Unknown shell tool: " + shellConfig.getShellTool());
        };
    }
}
