package com.reajason.javaweb.integration.springwebflux;

import com.reajason.javaweb.integration.TestCasesProvider;
import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.neoGeorgDockerfile;
import static com.reajason.javaweb.integration.ContainerTool.springBoot2WebfluxDockerfile;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot2WebFluxContainerTest {
    public static final String imageName = "springboot2-webflux";

    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(springBoot2WebfluxDockerfile))
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.SpringWebFlux;
        List<String> supportedShellTypes = List.of(ShellType.SPRING_WEBFLUX_WEB_FILTER, ShellType.SPRING_WEBFLUX_HANDLER_METHOD, ShellType.NETTY_HANDLER);
        List<Packers> testPackers = List.of(Packers.Base64);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info("container stopped, logs is : {}", logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.SpringWebFlux, shellType, shellTool, Opcodes.V1_8, packer, container, python);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
