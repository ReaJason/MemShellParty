package com.reajason.javaweb.integration.wildfly;

import com.reajason.javaweb.memshell.server.UndertowShell;
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
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/10
 */
@Slf4j
@Testcontainers
public class Wildfly30ContainerTest {
    public static final String imageName = "quay.io/wildfly/wildfly:30.0.1.Final-jdk17";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/opt/jboss/wildfly/standalone/deployments/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(jbossPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.JAKARTA_SERVLET, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_SERVLET, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_SERVLET, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_SERVLET, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Godzilla, Packers.AgentJar)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.Undertow, shellType, shellTool, Opcodes.V17, packer, container);
    }
}
