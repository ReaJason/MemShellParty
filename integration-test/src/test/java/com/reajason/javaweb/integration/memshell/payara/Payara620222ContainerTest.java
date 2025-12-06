package com.reajason.javaweb.integration.memshell.payara;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.integration.TestCasesProvider;
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
import org.junit.jupiter.params.provider.ValueSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class Payara620222ContainerTest {
    public static final String imageName = "reajason/payara:6.2022.2-jdk11";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/usr/local/payara6/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forLogMessage(".*JMXService.*", 1))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        String server = Server.GlassFish;
        List<String> supportedShellTypes = List.of(
                ShellType.JAKARTA_FILTER,
                ShellType.JAKARTA_LISTENER,
                ShellType.JAKARTA_VALVE,
                ShellType.AGENT_FILTER_CHAIN,
                ShellType.CATALINA_AGENT_CONTEXT_VALVE
        );
        List<Packers> testPackers = List.of(Packers.JSP);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, null, List.of(ShellTool.AntSword));
    }

    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/test"));
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
//        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        shellInjectIsOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V11, packer, container, python);
    }

    @ParameterizedTest
    @ValueSource(strings = {ShellType.JAKARTA_FILTER,
            ShellType.JAKARTA_LISTENER,
            ShellType.JAKARTA_VALVE,})
    void testProbeInject(String shellType) {
        String url = getUrl(container);
        ShellAssertion.testProbeInject(url, Server.GlassFish, shellType, Opcodes.V11);
    }
}
