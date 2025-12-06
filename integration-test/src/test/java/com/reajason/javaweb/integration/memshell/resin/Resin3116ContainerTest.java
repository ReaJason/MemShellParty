package com.reajason.javaweb.integration.memshell.resin;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.integration.TestCasesProvider;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
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
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Resin3116ContainerTest {
    public static final String imageName = "reajason/resin:3.1.16";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/resin3/webapps/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(resinPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        String server = Server.Resin;
        List<String> supportedShellTypes = List.of(
                ShellType.FILTER,
                ShellType.LISTENER,
                ShellType.AGENT_FILTER_CHAIN
        );
        List<Packers> testPackers = List.of(Packers.JSP);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
    }

    @AfterAll
    @SneakyThrows
    static void tearDown() {
        Thread.sleep(1000);
        String logs = container.getLogs();
        log.info(logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        shellInjectIsOk(getUrl(container), Server.Resin, shellType, shellTool, Opcodes.V1_6, packer, container, python);
    }

    @ParameterizedTest
    @ValueSource(strings = {ShellType.FILTER,
            ShellType.LISTENER,})
    void testProbeInject(String shellType) {
        String url = getUrl(container);
        ShellAssertion.testProbeInject(url, Server.Resin, shellType, Opcodes.V1_6);
    }
}