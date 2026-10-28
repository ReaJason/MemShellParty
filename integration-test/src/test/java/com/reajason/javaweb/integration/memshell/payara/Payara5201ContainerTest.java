package com.reajason.javaweb.integration.memshell.payara;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.containers.wait.strategy.WaitAllStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.List;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class Payara5201ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.glassFish(
            "reajason/payara:5.201",
            "/usr/local/payara5/glassfish/domains/domain1/autodeploy/app.war")
            .targetJdkVersion(Opcodes.V1_6)
            .waitStrategy(new WaitAllStrategy()
                    .withStrategy(Wait.forSuccessfulCommand(
                            "test $(grep -c 'JMXService' /usr/local/payara5/glassfish/domains/domain1/logs/server.log 2>/dev/null) -ge 2"))
                    .withStrategy(Wait.forHttp("/app/test"))
                    .withStartupTimeout(Duration.ofMinutes(5)))
            .agentPersistReadyLog("JMXService")
            .agentPersist(true)
            .filelessAgent(true)
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET
            ))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network)
            // ARM64 的 libinstrument 内部符号被剥离，使用支持调用图恢复的 amd64 变体。
            .withCreateContainerCmdModifier(command -> command.withPlatform("linux/amd64"));

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
