package com.reajason.javaweb.integration.memshell.resin;

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
 * @since 2026/7/4
 */
@Testcontainers
public class Resin2117ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .builder()
            .imageName("reajason/resin:2.1.17-jdk6")
            .server(Server.Resin2)
            .warFile(ContainerTool.servlet2WarFile)
            .warDeployPath("/usr/local/resin2/webapps/app.war")
            .pidScript(ContainerTool.resinPid)
            .targetJdkVersion(Opcodes.V1_6)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER
            ))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER
            ))
            .enableJspPackerTest(false)
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
