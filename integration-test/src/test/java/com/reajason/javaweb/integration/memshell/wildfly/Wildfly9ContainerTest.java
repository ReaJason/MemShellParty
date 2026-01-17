package com.reajason.javaweb.integration.memshell.wildfly;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.apache.commons.lang3.tuple.Triple;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

/**
 * <a href="https://hub.docker.com/r/jboss/wildfly/tags">Wildfly - DockerHub</a>
 * <a href="https://quay.io/repository/wildfly/wildfly?tab=tags">Wildfly - Quay</a>
 *
 * @author ReaJason
 * @since 2024/12/10
 */
@Testcontainers
public class Wildfly9ContainerTest extends AbstractContainerTest {

    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .undertow(
                    "jboss/wildfly:9.0.1.Final",
                    "/opt/jboss/wildfly/standalone/deployments/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.UNDERTOW_AGENT_SERVLET_HANDLER
            ))
            .testPackers(List.of(Packers.JSP))
            .unSupportedCases(List.of(
                    Triple.of(ShellType.UNDERTOW_AGENT_SERVLET_HANDLER, ShellTool.AntSword, Packers.AgentJar)
            ))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER
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
