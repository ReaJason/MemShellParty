package com.reajason.javaweb.integration.memshell.tomcat;

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
 * @since 2024/12/4
 */
@Testcontainers
public class Tomcat11JRE21ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.tomcat("tomcat:11.0-jre21")
            .warFile(warJakartaFile)
            .jakarta(true)
            .targetJdkVersion(Opcodes.V21)
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_VALVE,
                    ShellType.JAKARTA_PROXY_VALVE,
                    ShellType.JAKARTA_WEBSOCKET,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.JSP, Packers.AgentJarWithJREAttacher))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .probeShellTypes(List.of(
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_VALVE,
                    ShellType.JAKARTA_PROXY_VALVE,
                    ShellType.JAKARTA_WEBSOCKET
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
