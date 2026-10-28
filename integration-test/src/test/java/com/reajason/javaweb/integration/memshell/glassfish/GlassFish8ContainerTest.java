package com.reajason.javaweb.integration.memshell.glassfish;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Map;

import static com.reajason.javaweb.integration.ContainerTool.warJakartaFile;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Testcontainers
public class GlassFish8ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.glassFish(
                    "reajason/glassfish:8.0.3-jdk21",
                    "/usr/local/glassfish8/glassfish/domains/domain1/autodeploy/app.war")
            .waitStrategy(Wait.forLogMessage(".*JMXService.*", 1))
            .warFile(warJakartaFile)
            .jakarta(true)
            .targetJdkVersion(Opcodes.V21)
            // ENTRYPOINT 会重复创建占位 -Dhei，并在 set -e 下导致第二次启动退出。
            .env(Map.of("JAVA_OPTS", ""))
            .agentPersistReadyLog("JMXService")
            .agentPersist(true)
            .filelessAgent(true)
            .supportedShellTypes(List.of(
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_VALVE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE,
                    ShellType.JAKARTA_WEBSOCKET,
                    ShellType.JAKARTA_RAW_WEBSOCKET
            ))
            .unSupportedShellTools(List.of(ShellTool.AntSword))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.JAKARTA_FILTER,
                    ShellType.JAKARTA_LISTENER,
                    ShellType.JAKARTA_VALVE,
                    ShellType.JAKARTA_WEBSOCKET,
                    ShellType.JAKARTA_RAW_WEBSOCKET
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
