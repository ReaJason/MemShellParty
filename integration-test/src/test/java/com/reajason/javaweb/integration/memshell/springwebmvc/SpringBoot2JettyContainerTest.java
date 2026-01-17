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
public class SpringBoot2JettyContainerTest extends AbstractContainerTest {

    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:8u472-b08-jdk")
            .jarFile(ContainerTool.springBoot2JettyJarFile)
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
            .testPackers(List.of(Packers.SpEL))
            .build();

    private static final ContainerTestConfig JETTY_CONFIG = ContainerTestConfig.builder()
            .imageName("springboot2-jetty")
            .server(Server.Jetty)
            .serverVersion("7+")
            .targetJdkVersion(Opcodes.V1_8)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.HANDLER,
                    ShellType.CUSTOMIZER,
                    ShellType.JETTY_AGENT_HANDLER
            ))
            .testPackers(List.of(Packers.SpEL))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network);

    static Stream<org.junit.jupiter.params.provider.Arguments> jettyCasesProvider() {
        return generateTestCases(JETTY_CONFIG);
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("jettyCasesProvider")
    void testJetty(String imageName, String shellType, String shellTool, Packers packer) {
        runShellInject(JETTY_CONFIG, shellType, shellTool, packer);
    }

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
