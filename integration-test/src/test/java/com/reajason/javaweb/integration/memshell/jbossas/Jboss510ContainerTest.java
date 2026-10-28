package com.reajason.javaweb.integration.memshell.jbossas;

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
 * @since 2024/12/10
 */
@Testcontainers
public class Jboss510ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.jboss(
            "reajason/jboss:5-jdk6",
            "/usr/local/jboss/server/web/deploy/app.war")
            .warFile(ContainerTool.servlet2WarFile)
            .targetJdkVersion(Opcodes.V1_6)
            .agentPersist(true)
            .filelessAgent(true)
            .supportedShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE,
                    ShellType.AGENT_FILTER_CHAIN,
                    ShellType.CATALINA_AGENT_CONTEXT_VALVE,
                    ShellType.RAW_WEBSOCKET
            ))
            .testPackers(List.of(Packers.JSP))
            .unSupportedShellTools(List.of(ShellTool.Behinder))
            .probeShellTypes(List.of(
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.VALVE,
                    ShellType.PROXY_VALVE,
                    ShellType.RAW_WEBSOCKET
            ))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network)
            // 容器停止会留下 Hypersonic 锁文件，启动前清理，避免旧锁阻止新 JVM 初始化。
            .withCreateContainerCmdModifier(command -> command.withEntrypoint(
                    "/bin/sh", "-c", "rm -f /usr/local/jboss/server/web/data/hypersonic/localDB.lck; "
                            + "exec /usr/local/jboss/bin/run.sh -c web -b 0.0.0.0"));

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
