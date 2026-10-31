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
public class WebSphere85524ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.webSphere(
            "reajason/websphere:8.5.5.24",
            "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/monitoredDeployableApps/servers/server1/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .waitStrategy(Wait.forLogMessage(".*CWLDD0021I.*", 1)
                    .withStartupTimeout(Duration.ofMinutes(5)))
            // 镜像启动时 configure.sh 会先起停一次 server；正式启动后 deploy-monitor 会 touch
            // app.war，触发监视目录把应用停掉再重新部署。该 touch 只为首次部署：持久化用例重启前
            // 去掉它，重启就只是恢复服务，不会在请求窗口里插入一次应用重部署。
            .agentPersistReadyLog("+ deploy-monitor:")
            .agentPersistPrepareCommand("sed -i '/-exec touch/d' /work/deploy-monitor.sh")
            .healthCheckPath("/app/")
            .agentPersist(true)
            .filelessAgent(true)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.WAS_AGENT_FILTER_MANAGER,
                    ShellType.RAW_WEBSOCKET
            ))
            .testPackers(List.of(Packers.JSP))
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

    @Test
    void testListProcessAndAttachAll() {
        ShellAssertion.testListProcessAndAttachAll(getUrl(), getConfig(), ShellType.WAS_AGENT_FILTER_MANAGER, getContainer());
    }
}
