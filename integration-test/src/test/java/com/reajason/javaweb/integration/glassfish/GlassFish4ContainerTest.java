package com.reajason.javaweb.integration.glassfish;

import com.reajason.javaweb.integration.TestCasesProvider;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class GlassFish4ContainerTest {
    public static final String imageName = "reajason/glassfish:4.1.2-quick";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/glassfish4/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forLogMessage(".*(done|deployed).*", 1).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(8080);

    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/"));
    }

    static Stream<Arguments> casesProvider() {
        Server server = Server.GlassFish;
        List<String> supportedShellTypes = List.of(
                ShellType.FILTER, ShellType.LISTENER, ShellType.VALVE,
                ShellType.AGENT_FILTER_CHAIN,
                ShellType.CATALINA_AGENT_CONTEXT_VALVE
        );
        List<Packers> testPackers = List.of(Packers.JSP, Packers.JSPX, Packers.JavaDeserialize);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
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
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer, container, python);
    }
}
