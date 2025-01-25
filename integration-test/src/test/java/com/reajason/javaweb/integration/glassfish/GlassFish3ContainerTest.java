package com.reajason.javaweb.integration.glassfish;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packers;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
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
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class GlassFish3ContainerTest {
    public static final String imageName = "reajason/glassfish:3.1.2.2-jdk6";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/glassfish3/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .waitingFor(Wait.forLogMessage(".*(done|deployed).*", 1).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(8080);

    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/"));
    }

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packers.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packers.Deserialize),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Command, Packers.AgentJar),
//                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packer.INSTANCE.AgentJar), // classFormatError
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Command, Packers.AgentJar),
//                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packer.INSTANCE.AgentJar),
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
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
