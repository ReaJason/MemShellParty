package com.reajason.javaweb.integration.memshell.weblogic;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellTool;
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
public class WebLogic15110ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.webLogic(
            "reajason/weblogic:15.1.1.0-jdk21",
            "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
            .targetJdkVersion(Opcodes.V21)
            .warFile(ContainerTool.warJakartaFile)
            .jakarta(true)
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_WEBSOCKET,
                    ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT
            ))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .testPackers(List.of(Packers.Base64))
            .probeShellTypes(List.of(
                    ShellType.JAKARTA_SERVLET,
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER
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
