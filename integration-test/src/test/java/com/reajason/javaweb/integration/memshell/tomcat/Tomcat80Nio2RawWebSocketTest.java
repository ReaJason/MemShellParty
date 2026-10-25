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
 * Tomcat 8.0 的 NIO2 连接器把 coyote buffer 绑到 SocketWrapper&lt;Nio2Channel&gt;，
 * RawWebSocket 通过 Nio2Channel 的 Future 式 read/write 接管连接。
 *
 * @author ReaJason
 * @since 2026/10/25
 */
@Testcontainers
public class Tomcat80Nio2RawWebSocketTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig.tomcat("tomcat:8.0.53-jre8")
            .dockerfilePath(ContainerTool.tomcat80Nio2Dockerfile)
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
