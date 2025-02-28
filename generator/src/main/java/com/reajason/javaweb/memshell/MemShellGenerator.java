package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import com.reajason.javaweb.memshell.server.AbstractShell;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    public static GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        Server server = shellConfig.getServer();
        AbstractShell shell = server.getShell();
        if (shell == null) {
            throw new IllegalArgumentException("Unsupported server");
        }
        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(CommonUtil.generateShellClassName(server, shellConfig.getShellType()));
        }

        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }

        Pair<Class<?>, Class<?>> shellInjectorPair = shellConfig.getServer().getShell().getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
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

    private static byte[] generateShellBytes(ShellConfig shellConfig, ShellToolConfig shellToolConfig) {
        switch (shellConfig.getShellTool()) {
            case Godzilla:
                return new GodzillaGenerator(shellConfig, (GodzillaConfig) shellToolConfig).getBytes();
            case Command:
                return new CommandGenerator(shellConfig, (CommandConfig) shellToolConfig).getBytes();
            case Behinder:
                return new BehinderGenerator(shellConfig, (BehinderConfig) shellToolConfig).getBytes();
            case Suo5:
                return new Suo5Generator(shellConfig, ((Suo5Config) shellToolConfig)).getBytes();
            case AntSword:
                return new AntSwordGenerator(shellConfig, (AntSwordConfig) shellToolConfig).getBytes();
            case NeoreGeorg:
                return new NeoreGeorgGenerator(shellConfig, (NeoreGeorgConfig) shellToolConfig).getBytes();
            default:
                throw new UnsupportedOperationException("Unknown shell tool: " + shellConfig.getShellTool());
        }
    }
}