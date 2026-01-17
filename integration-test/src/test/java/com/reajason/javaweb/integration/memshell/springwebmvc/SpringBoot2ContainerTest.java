package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
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
public class SpringBoot2ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:8u472-b08-jdk")
            .jarFile(ContainerTool.springBoot2JarFile)
            .jarDeployPath("/app/app.jar")
            .command("java -jar /app/app.jar")
            .server(Server.SpringWebMvc)
            .pidScript(ContainerTool.javaPid)
            .enableJspPackerTest(false)
            .targetJdkVersion(Opcodes.V1_8)
            .contextPath("")
            .healthCheckPath("/test")
            .supportedShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER,
                    ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET
            ))
            .testPackers(List.of(Packers.H2JS))
            .probeShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER
            ))
            .build();

    private static final ContainerTestConfig TOMCAT_CONFIG = ContainerTestConfig.builder()
            .imageName("springboot-2")
            .server(Server.Tomcat)
            .targetJdkVersion(Opcodes.V1_8)
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.VALVE,
                    ShellType.WEBSOCKET,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.H2JS))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network);

    static Stream<Arguments> tomcatCasesProvider() {
        return generateTestCases(TOMCAT_CONFIG);
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("tomcatCasesProvider")
    void testTomcat(String imageName, String shellType, String shellTool, Packers packer) {
        runShellInject(TOMCAT_CONFIG, shellType, shellTool, packer);
    }

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
