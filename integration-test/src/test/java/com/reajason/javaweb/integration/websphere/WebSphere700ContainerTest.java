package com.reajason.javaweb.integration.websphere;

import com.reajason.javaweb.memshell.WebSphereShell;
import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packer;
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
public class WebSphere700ContainerTest {
    public static final String imageName = "reajason/websphere:7.0.0.21";
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
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Command, Packer.INSTANCE.AgentJar),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Behinder, Packer.INSTANCE.AgentJar),
                arguments(imageName, WebSphereShell.AGENT_FILTER_MANAGER, ShellTool.Godzilla, Packer.INSTANCE.AgentJar)
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
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
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
