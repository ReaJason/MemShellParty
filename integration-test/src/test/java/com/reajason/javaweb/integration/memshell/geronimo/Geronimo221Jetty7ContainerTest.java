package com.reajason.javaweb.integration.memshell.geronimo;

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
public class Geronimo221Jetty7ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .builder()
            .server(Server.Jetty)
            .imageName("reajason/geronimo:2.2.1-jetty7")
            .warFile(ContainerTool.warFile)
            .warDeployPath("/opt/geronimo/deploy/app.war")
            .pidScript(ContainerTool.javaPid)
            .serverVersion("7+")
            .targetJdkVersion(Opcodes.V1_6)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER,
                    ShellType.JETTY_AGENT_HANDLER
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER
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
