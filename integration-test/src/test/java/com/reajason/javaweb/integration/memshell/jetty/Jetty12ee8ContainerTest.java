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
public class Jetty12ee8ContainerTest extends AbstractContainerTest {
    private static final ContainerTestConfig CONFIG = ContainerTestConfig
            .jetty("reajason/jetty:12.0-jre21-ee8")
            .command("java -jar /usr/local/jetty/start.jar --modules=ee8-websocket-javax")
            .serverVersion("12")
            .targetJdkVersion(Opcodes.V21)
            .probeTargetJdkVersion(Opcodes.V17)
            .supportedShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET,
                    ShellType.JETTY_AGENT_HANDLER
            ))
            .testPackers(List.of(Packers.DefaultBase64))
            .probeShellTypes(List.of(
                    ShellType.SERVLET,
                    ShellType.FILTER,
                    ShellType.LISTENER,
                    ShellType.HANDLER,
                    ShellType.WEBSOCKET,
                    ShellType.RAW_WEBSOCKET
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
