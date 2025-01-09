package com.reajason.javaweb.integration.glassfish;

import com.reajason.javaweb.memshell.config.Constants;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packer;
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
public class GlassFish4ContainerTest {
    public static final String imageName = "reajason/glassfish:4.1.2-quick";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/glassfish4/glassfish/domains/domain1/autodeploy/app.war")
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
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.VALVE, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Command, Packer.INSTANCE.AgentJar),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packer.INSTANCE.AgentJar),
                arguments(imageName, Constants.AGENT_FILTER_CHAIN, ShellTool.Behinder, Packer.INSTANCE.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Command, Packer.INSTANCE.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Behinder, Packer.INSTANCE.AgentJar),
                arguments(imageName, Constants.AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packer.INSTANCE.AgentJar)
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
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
