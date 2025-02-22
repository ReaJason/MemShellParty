package com.reajason.javaweb.memshell.tomcat.command;

import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.CommandGenerator;
import com.reajason.javaweb.memshell.shelltool.command.CommandFilter;
import com.reajason.javaweb.memshell.shelltool.command.CommandValve;
import com.reajason.javaweb.util.ClassUtils;
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
        CommandConfig shellConfig = CommandConfig.builder()
                .shellClass(clazz)
                .shellClassName(className)
                .paramName("cmd")
                .build();
        generateConfig.setShellType(shellType);
        byte[] bytes = CommandGenerator.generate(generateConfig, shellConfig);
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(shellConfig.getShellClassName(), obj.getClass().getName());
        assertEquals(shellConfig.getParamName(), ClassUtils.getFieldValue(obj, "paramName"));
    }
}