package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.stream.Stream;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
public class SpringBoot2UndertowContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:8u472-b08-jdk")
            .jarFile(ContainerTool.springBoot2UndertowJarFile)
            .jarDeployPath("/app/app.jar")
            .command("java -jar /app/app.jar")
            .server(Server.SpringWebMvc)
            .pidScript(ContainerTool.springbootPid)
            .enableJspPackerTest(false)
            .targetJdkVersion(Opcodes.V1_8)
            .contextPath("")
            .healthCheckPath("/test")
            .supportedShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER,
                    ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET
            ))
            .testPackers(List.of(Packers.ScriptEngine, Packers.SpEL, Packers.Base64))
            .build();

    private static final ContainerTestConfig UNDERTOW_CONFIG = ContainerTestConfig.builder()
            .imageName("springboot2-undertow")
            .server(Server.Undertow)
            .targetJdkVersion(Opcodes.V1_8)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.UNDERTOW_AGENT_SERVLET_HANDLER
            ))
            .testPackers(List.of(Packers.SpEL))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network);

    static Stream<org.junit.jupiter.params.provider.Arguments> undertowCasesProvider() {
        return generateTestCases(UNDERTOW_CONFIG);
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("undertowCasesProvider")
    void testUndertow(String imageName, String shellType, String shellTool, Packers packer) {
        runShellInject(UNDERTOW_CONFIG, shellType, shellTool, packer);
    }

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
