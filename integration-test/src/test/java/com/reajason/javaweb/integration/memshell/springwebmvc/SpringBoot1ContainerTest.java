package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
public class SpringBoot1ContainerTest extends AbstractContainerTest {

    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:8u472-b08-jdk")
            .jarFile(ContainerTool.springBoot1JarFile)
            .jarDeployPath("/app/app.jar")
            .command("java -jar /app/app.jar")
            .server(Server.SpringWebMvc)
            .pidScript(ContainerTool.springbootPid)
            .targetJdkVersion(Opcodes.V1_8)
            .enableJspPackerTest(false)
            .contextPath("")
            .healthCheckPath("/test")
            .supportedShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER,
                    ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET
            ))
            .testPackers(List.of(Packers.SpEL))
            .probeShellTypes(List.of(
                    ShellType.SPRING_WEBMVC_INTERCEPTOR,
                    ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER
            ))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network);

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
