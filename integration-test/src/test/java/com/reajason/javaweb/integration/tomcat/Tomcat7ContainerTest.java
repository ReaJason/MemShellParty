package com.reajason.javaweb.integration.tomcat;

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
public class Tomcat7ContainerTest {
    public static final String imageName = "tomcat:7.0.85-jre7";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(tomcatPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.SERVLET, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.SERVLET, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.SERVLET, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.SERVLET, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.SERVLET, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.SERVLET, ShellTool.AntSword, Packers.JavaDeserialize),
                arguments(imageName, ShellType.FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.FILTER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.FILTER, ShellTool.AntSword, Packers.JavaDeserialize),
                arguments(imageName, ShellType.LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.LISTENER, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.AntSword, Packers.JavaDeserialize),
                arguments(imageName, ShellType.VALVE, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.VALVE, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.VALVE, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.VALVE, ShellTool.AntSword, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.AntSword, Packers.JavaDeserialize),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.AntSword, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_CONTEXT_VALVE, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_CONTEXT_VALVE, ShellTool.AntSword, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_CONTEXT_VALVE, ShellTool.Behinder, Packers.AgentJar)
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
        testShellInjectAssertOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_7, packer, container);
    }
}