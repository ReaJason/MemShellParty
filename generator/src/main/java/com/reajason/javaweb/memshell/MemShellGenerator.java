package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.generator.InjectorGenerator;
import com.reajason.javaweb.memshell.server.AbstractShell;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    public static MemShellResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        Server server = shellConfig.getServer();
        AbstractShell shell = server.getShell();
        if (shell == null) {
            throw new IllegalArgumentException("Unsupported server: " + server);
        }

        if (StringUtils.isBlank(shellToolConfig.getShellClassName())) {
            shellToolConfig.setShellClassName(CommonUtil.generateShellClassName(server, shellConfig.getShellType()));
        }

        if (StringUtils.isBlank(injectorConfig.getInjectorClassName())) {
            injectorConfig.setInjectorClassName(CommonUtil.generateInjectorClassName());
        }

        Class<?> injectorClass = null;

        if (ShellTool.Custom.equals(shellConfig.getShellTool())) {
            injectorClass = shellConfig.getServer().getShell().getShellInjectorMapping().getInjector(shellConfig.getShellType());
        } else {
            Pair<Class<?>, Class<?>> shellInjectorPair = shellConfig.getServer().getShell().getShellInjectorPair(shellConfig.getShellTool(), shellConfig.getShellType());
            if (shellInjectorPair == null) {
                throw new UnsupportedOperationException(server + " unsupported shell type: " + shellConfig.getShellType() + " for tool: " + shellConfig.getShellTool());
            }
            Class<?> shellClass = shellInjectorPair.getLeft();
            injectorClass = shellInjectorPair.getRight();
            shellToolConfig.setShellClass(shellClass);
        }

        byte[] shellBytes = shellConfig.getShellTool().generateBytes(shellConfig, shellToolConfig);

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