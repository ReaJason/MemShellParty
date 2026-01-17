package com.reajason.javaweb.integration.memshell.jbossas;

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
 * @since 2024/12/10
 */
@Testcontainers
public class Jboss711ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.jboss(
            "reajason/jboss:7-jdk7",
            "/usr/local/jboss/standalone/deployments/app.war")
            .targetJdkVersion(Opcodes.V1_7)
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE
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
