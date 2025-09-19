package com.reajason.javaweb.memshell;

import com.reajason.javaweb.GenerationException;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.server.AbstractServer;
import com.reajason.javaweb.utils.CommonUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    public static MemShellResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        String serverName = shellConfig.getServer();
        AbstractServer server = ServerFactory.getServer(serverName);
        if (server == null) {
            throw new GenerationException("Unsupported server: " + serverName);
        }
        Class<?> injectorClass = null;

        if (ShellTool.Custom.equals(shellConfig.getShellTool())) {
            injectorClass = server.getShellInjectorMapping().getInjector(shellConfig.getShellType());
        } else {
            Pair<Class<?>, Class<?>> shellInjectorPair = server.getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
            if (shellInjectorPair == null) {
                throw new GenerationException(serverName + " unsupported shell type: " + shellConfig.getShellType() + " for tool: " + shellConfig.getShellTool());
            }
            Class<?> shellClass = shellInjectorPair.getLeft();
            injectorClass = shellInjectorPair.getRight();
            shellToolConfig.setShellClass(shellClass);
            if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
                shellToolConfig.setShellClassName(CommonUtil.generateShellClassName(serverName, shellConfig.getShellType()));
            }
        }

        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }

        byte[] shellBytes = ShellToolFactory.generateBytes(shellConfig, shellToolConfig);

        injectorConfig.setInjectorClass(injectorClass);
        injectorConfig.setShellClassName(shellToolConfig.getShellClassName());
        injectorConfig.setShellClassBytes(shellBytes);

        InjectorGenerator injectorGenerator = new InjectorGenerator(shellConfig, injectorConfig);
        byte[] injectorBytes = injectorGenerator.generate();
        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();

        return MemShellResult.builder()
                .shellConfig(shellConfig)
                .shellToolConfig(shellToolConfig)
                .injectorConfig(injectorConfig)
                .shellClassName(shellToolConfig.getShellClassName())
                .shellBytes(shellBytes)
                .injectorClassName(injectorConfig.getInjectorClassName())
                .injectorBytes(injectorBytes)
                .injectorInnerClassBytes(innerClassBytes)
                .build();
    }
}