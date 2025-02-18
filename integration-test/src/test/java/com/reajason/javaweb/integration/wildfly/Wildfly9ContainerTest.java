package com.reajason.javaweb.integration.wildfly;

import com.reajason.javaweb.memshell.UndertowShell;
import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packers;
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
 * <a href="https://hub.docker.com/r/jboss/wildfly/tags">Wildfly - DockerHub</a>
 * <a href="https://quay.io/repository/wildfly/wildfly?tab=tags">Wildfly - Quay</a>
 *
 * @author ReaJason
 * @since 2024/12/10
 */
@Slf4j
@Testcontainers
public class Wildfly9ContainerTest {
    public static final String imageName = "jboss/wildfly:10.0.0.Final";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/opt/jboss/wildfly/standalone/deployments/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(jbossPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packers.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packers.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Suo5, Packers.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.AntSword, Packers.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Suo5, Packers.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.AntSword, Packers.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Suo5, Packers.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.AntSword, Packers.ScriptEngine),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.AntSword, Packers.AgentJar),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, UndertowShell.AGENT_SERVLET_HANDLER, ShellTool.Behinder, Packers.AgentJar)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.Undertow, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
