package com.reajason.javaweb.integration.memshell.jetty;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

import static com.reajason.javaweb.integration.ContainerTool.warJakartaFile;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
@Testcontainers
public class Jetty11ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .jetty("jetty:11.0-jre17")
            .warFile(warJakartaFile)
            .serverVersion("7+")
            .jakarta(true)
            .targetJdkVersion(Opcodes.V17)
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_HANDLER,
                    ShellType.CUSTOMIZER,
                    ShellType.JETTY_AGENT_HANDLER
            ))
            .testPackers(List.of(Packers.JSP))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .probeShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_HANDLER,
                    ShellType.CUSTOMIZER
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
