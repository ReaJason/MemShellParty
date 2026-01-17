package com.reajason.javaweb.integration.memshell.glassfish;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.tuple.Triple;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class GlassFish3ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.glassFish(
            "reajason/glassfish:3.1.2.2-jdk6",
            "/usr/local/glassfish3/glassfish/domains/domain1/autodeploy/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .waitStrategy(Wait.forLogMessage(".*(deployed|done).*", 1))
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE
            ))
            .testPackers(List.of(Packers.JSP))
            .unSupportedCases(List.of(
                    Triple.of(ShellType.AGENT_FILTER_CHAIN, ShellTool.Suo5v2, Packers.AgentJar),
                    Triple.of(ShellType.CATALINA_AGENT_CONTEXT_VALVE, ShellTool.Suo5v2, Packers.AgentJar)
            ))
            .probeShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE
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
