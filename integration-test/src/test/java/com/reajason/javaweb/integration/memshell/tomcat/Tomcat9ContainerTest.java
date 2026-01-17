package com.reajason.javaweb.integration.memshell.tomcat;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
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
 * @since 2024/12/4
 */
@Testcontainers
public class Tomcat9ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.tomcat("tomcat:9-jre9")
            .targetJdkVersion(Opcodes.V9)
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.SERVLET,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE,
                    ShellType.WEBSOCKET,
                    ShellType.UPGRADE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.JSP, Packers.ScriptEngine, Packers.AgentJarWithJREAttacher))
            .probeShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.SERVLET,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE,
                    ShellType.WEBSOCKET
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
