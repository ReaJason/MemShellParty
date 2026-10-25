package com.reajason.javaweb.integration.memshell.tomcat;

import com.reajason.javaweb.integration.AbstractContainerTest;
import com.reajason.javaweb.integration.ContainerTestConfig;
import com.reajason.javaweb.integration.ContainerTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import net.bytebuddy.jar.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;

/**
 * Tomcat 8.0 默认连接器是 NIO（未装 tcnative 时），RawWebSocket 走的是
 * NioSelectorPool/NioChannel 这条 8.0 独有的裸连接路径。
 *
 * @author ReaJason
 * @since 2026/10/25
 */
@Testcontainers
public class Tomcat80NioRawWebSocketTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.tomcat("tomcat:8.0.53-jre8")
            .dockerfilePath(ContainerTool.tomcat80NioDockerfile)
            .targetJdkVersion(Opcodes.V1_8)
            .enableJspPackerTest(false)
            .supportedShellTypes(List.of(ShellType.RAW_WEBSOCKET))
            .testPackers(List.of(Packers.DefaultBase64))
            .probeShellTypes(List.of(ShellType.RAW_WEBSOCKET))
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
