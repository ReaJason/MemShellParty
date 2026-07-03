package com.reajason.javaweb.integration.memshell.jetty;

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
 * @since 2024/12/7
 */
@Testcontainers
public class Jetty51ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.
            builder()
            .imageName("reajason/jetty:5.1.10-jdk6")
            .server(Server.Jetty5)
            .pidScript(ContainerTool.jettyPid)
            .warFile(ContainerTool.servlet2WarFile)
            .warDeployPath("/usr/local/jetty/webapps/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.LISTENER,
                    ShellType.FILTER
            ))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER
            ))
            .testPackers(List.of(Packers.JSP))
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
