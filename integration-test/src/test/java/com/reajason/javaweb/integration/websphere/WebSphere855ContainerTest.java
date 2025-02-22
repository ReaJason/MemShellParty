package com.reajason.javaweb.integration.websphere;

import com.reajason.javaweb.memshell.server.WebSphereShell;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.Packers;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
@Slf4j
public class WebSphere855ContainerTest {
    public static final String imageName = "reajason/websphere:8.5.5.24";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withFileSystemBind(warFile.getFilesystemPath(), "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/monitoredDeployableApps/servers/server1/app.war", BindMode.READ_WRITE)
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(webspherePid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app/").forPort(9080).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(9080)
            .withPrivilegedMode(true);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.SERVLET, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.AntSword, Packers.AgentJar),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Godzilla, Packers.AgentJar)

        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info("container stopped, logs is : {}", logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.WebSphere, shellType, shellTool, Opcodes.V1_6, packer, container);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(9080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
