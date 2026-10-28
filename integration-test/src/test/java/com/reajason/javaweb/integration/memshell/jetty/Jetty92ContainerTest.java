package com.reajason.javaweb.integration.memshell.jetty;

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
 * @since 2024/12/7
 */
@Testcontainers
public class Jetty92ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .jetty("jetty:9.2-jre7")
            .serverVersion("7+")
            .targetJdkVersion(Opcodes.V1_6)
            .agentPersist(true)
            .filelessAgent(true)
            // JDK7/ARM 的优雅停机会在 NativeThread.signal 失败，直接停止容器验证离线替换。
            .agentPersistForceStop(true)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER,
                    ShellType.CUSTOMIZER,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET,
                    ShellType.JETTY_AGENT_HANDLER
            ))
            .testPackers(List.of(Packers.JSP))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER,
                    ShellType.CUSTOMIZER,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET
            ))
            .build();

    static Network network = newNetwork();
    @Container
    public static final GenericContainer<?> python = buildPythonContainer(network);

    @Container
    public static final GenericContainer<?> container = buildContainer(CONFIG, network)
            // 官方镜像没有 arm64，避免在 Apple Silicon 上选中不支持的 32 位 ARM JRE。
            .withCreateContainerCmdModifier(command -> {
                command.withPlatform("linux/amd64");
                // 模块目录需要 root 写权限；旧 ENTRYPOINT 重读 jetty.start 时未去除续行符。
                command.withUser("root");
                command.withEntrypoint("/bin/sh", "-c", "rm -f /var/lib/jetty/jetty.start; "
                        + "exec /docker-entrypoint.sh java -jar /usr/local/jetty/start.jar");
            });

    @Override
    protected ContainerTestConfig getConfig() {
        return CONFIG;
    }
}
