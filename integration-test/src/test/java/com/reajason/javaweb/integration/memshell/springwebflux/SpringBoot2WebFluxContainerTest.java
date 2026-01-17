package com.reajason.javaweb.integration.memshell.springwebflux;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.integration.VulTool;
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
public class SpringBoot2WebFluxContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.builder()
            .imageName("eclipse-temurin:8u472-b08-jdk")
            .jarFile(ContainerTool.springBoot2WebfluxJarFile)
            .jarDeployPath("/app/app.jar")
            .command("java -jar /app/app.jar")
            .server(Server.SpringWebFlux)
            .targetJdkVersion(Opcodes.V1_8)
            .enableJspPackerTest(false)
            .contextPath("")
            .healthCheckPath("/test")
            .jattachFile(null)
            .supportedShellTypes(List.of(
                    ShellType.SPRING_WEBFLUX_WEB_FILTER,
                    ShellType.SPRING_WEBFLUX_HANDLER_METHOD,
                    ShellType.NETTY_HANDLER
            ))
            .testPackers(List.of(Packers.Base64))
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
