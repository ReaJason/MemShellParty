package com.reajason.javaweb.integration.glassfish;

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
import static com.reajason.javaweb.integration.ContainerTool.glassfishPid;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class GlassFish6ContainerTest {
    public static final String imageName = "reajason/glassfish:6.2.6-jdk11";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/usr/local/glassfish6/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .waitingFor(Wait.forLogMessage(".*deployed.*", 1))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_FILTER, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_LISTENER, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Behinder, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Godzilla, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Command, Packers.JavaDeserialize),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Suo5, Packers.JSP),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Suo5, Packers.JavaDeserialize),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packers.AgentJar),
                arguments(imageName, ShellType.AGENT_FILTER_CHAIN, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, ShellType.CATALINA_AGENT_CONTEXT_VALVE, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, ShellType.CATALINA_AGENT_CONTEXT_VALVE, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, ShellType.CATALINA_AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packers.AgentJar)
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
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
