package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellTool;
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
public class SpringBoot3ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:17.0.17_10-jdk")
            .jarFile(ContainerTool.springBoot3JarFile)
            .jakarta(true)
            .jarDeployPath("/app/app.jar")
            .command("java -jar /app/app.jar")
            .server(Server.SpringWebMvc)
            .pidScript(ContainerTool.springbootPid)
            .targetJdkVersion(Opcodes.V17)
            .enableJspPackerTest(false)
            .contextPath("")
            .healthCheckPath("/test")
            .supportedShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER,
                    ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET
            ))
            .testPackers(List.of(Packers.H2))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .probeShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER
            ))
            .build();

    private static final ContainerTestConfig TOMCAT_CONFIG = ContainerTestConfig.builder()
            .imageName("springboot3")
            .server(Server.Tomcat)
            .targetJdkVersion(Opcodes.V17)
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_FILTER,
//                ShellType.LISTENER,
                    ShellType.JAKARTA_VALVE,
                    ShellType.JAKARTA_WEBSOCKET,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.H2))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
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
