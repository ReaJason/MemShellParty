package com.reajason.javaweb.integration.memshell.weblogic;

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
 * @since 2024/12/24
 */
@Testcontainers
public class WebLogic1036ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.webLogic(
            "reajason/weblogic:10.3.6",
            "/opt/oracle/wls1036/user_projects/domains/base_domain/autodeploy/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .assertLogs(false)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT
            ))
            .testPackers(List.of(Packers.Base64))
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
