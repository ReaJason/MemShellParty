package com.reajason.javaweb.integration.memshell.websphere;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
public class WebSphere9051ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.webSphere(
            "reajason/websphere:9.0.5.1",
            "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/monitoredDeployableApps/servers/server1/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .waitStrategy(Wait.forLogMessage(".*WSVR0001I: Server server1 open for e-business.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(5)))
            // startServer.sh 的当前启动结果不会被 tail -F -n +0 重放。
            .agentPersistReadyLog("ADMU3000I: Server server1 open for e-business")
            .healthCheckPath("/app/")
            .agentPersist(true)
            .filelessAgent(true)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.WAS_AGENT_FILTER_MANAGER,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
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

    @Test
    void testListProcessAndAttachAll() {
        ShellAssertion.testListProcessAndAttachAll(getUrl(), getConfig(), ShellType.WAS_AGENT_FILTER_MANAGER, getContainer());
    }
}
