package com.reajason.javaweb.memshell;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.shelltool.behinder.BehinderConfig;
import com.reajason.javaweb.memshell.shelltool.command.CommandConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.memshell.shelltool.suo5.Suo5Config;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;

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
                .shellTool(ShellTool.Command)
                .shellType(ShellType.SERVLET)
                .targetJreVersion(Opcodes.V1_8)
                .debug(true)
                .shrink(true)
                .build();
        GodzillaConfig godzillaConfig = GodzillaConfig.builder()
                .pass("pass")
                .key("key")
                .headerName("User-Agent")
                .headerValue("test123").build();
        CommandConfig commandConfig = CommandConfig.builder()
                .paramName("param")
                .build();

        BehinderConfig behinderConfig = BehinderConfig.builder()
                .pass("test123")
                .headerName("User-Agent")
                .headerValue("test").build();

        Suo5Config suo5Config = Suo5Config.builder()
                .headerName("User-Agent")
                .headerValue("test").build();

        InjectorConfig injectorConfig = InjectorConfig.builder()
                .urlPattern("/v2")
                .staticInitialize(true)
                .build();

        MemShellResult generateResult = new MemShellGenerator().generate(shellConfig, injectorConfig, commandConfig);
        if (generateResult != null) {
            System.out.println(generateResult.getInjectorClassName());
            System.out.println(generateResult.getInjectorBytesBase64Str());
//            PackerRegistry.getInstance().get(Packers.GzipBase64).pack(generateResult.toClassPackerConfig());

//            Files.write(Paths.get("agent.jar"), ((JarPacker) PackerRegistry.getInstance().get(Packers.ScriptEngineJar)).packBytes(generateResult.toJarPackerConfig()));
//            System.out.println(generateResult.getShellBytes().length);
//            Files.write(Paths.get(generateResult.getInjectorClassName() + ".class"), generateResult.getInjectorBytes(), StandardOpenOption.CREATE_NEW);
//            Files.write(Paths.get(generateResult.getShellClassName() + ".class"), generateResult.getShellBytes(), StandardOpenOption.CREATE_NEW);
        }
    }
}
