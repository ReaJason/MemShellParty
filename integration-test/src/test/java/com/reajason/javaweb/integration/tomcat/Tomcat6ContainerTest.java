package com.reajason.javaweb.integration.tomcat;

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
import static com.reajason.javaweb.integration.ContainerTool.tomcatPid;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Tomcat6ContainerTest {
    public static final String imageName = "reajason/tomcat:6-jdk6";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(tomcatPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Suo5, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Suo5, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Suo5, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Suo5, Packers.Deserialize),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Behinder, Packers.AgentJar)
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
        testShellInjectAssertOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}