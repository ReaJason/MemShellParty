package com.reajason.javaweb.memshell.tomcat.godzilla;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.GodzillaConfig;
import com.reajason.javaweb.memshell.config.ShellConfig;
import com.reajason.javaweb.memshell.generator.GodzillaGenerator;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaFilter;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaListener;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaValve;
import com.reajason.javaweb.util.ClassUtils;
import com.reajason.javaweb.utils.CommonUtil;
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
class GodzillaTest {
    ShellConfig config = ShellConfig.builder().server(Server.Tomcat).build();
    GodzillaConfig.GodzillaConfigBuilder<?, ?> shellConfigBuilder = GodzillaConfig.builder()
            .pass(CommonUtil.getRandomString(6))
            .key(CommonUtil.getRandomString(6))
            .headerName("User-Agent")
            .headerValue(CommonUtil.getRandomString(5));

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(ShellType.FILTER, GodzillaFilter.class, "org.apache.utils.GodzillaFilter"),
                arguments(ShellType.LISTENER, GodzillaListener.class, "org.apache.utils.GodzillaListener"),
                arguments(ShellType.VALVE, GodzillaValve.class, "org.apache.utils.GodzillaValve")

        );
    }

    @ParameterizedTest
    @MethodSource("casesProvider")
    void generate(String shellType, Class<?> clazz, String className) {
        GodzillaConfig shellConfig = shellConfigBuilder
                .shellClassName(className)
                .shellClass(clazz)
                .build();
        config.setShellType(shellType);
        byte[] bytes = new GodzillaGenerator(config, shellConfig).getBytes();
        Object obj = ClassUtils.newInstance(bytes);
        assertEquals(shellConfig.getShellClassName(), obj.getClass().getName());
        assertEquals(shellConfig.getPass(), ClassUtils.getFieldValue(obj, "pass"));
        assertEquals(shellConfig.getHeaderName(), ClassUtils.getFieldValue(obj, "headerName"));
        assertEquals(shellConfig.getHeaderValue(), ClassUtils.getFieldValue(obj, "headerValue"));
    }
}