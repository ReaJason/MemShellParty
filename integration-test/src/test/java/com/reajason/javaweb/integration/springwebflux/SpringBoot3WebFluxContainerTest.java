package com.reajason.javaweb.integration.springwebflux;

import com.reajason.javaweb.memshell.SpringWebFluxShell;
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
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.springBoot3WebfluxDockerfile;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot3WebFluxContainerTest {
    public static final String imageName = "springboot3-webflux";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(springBoot3WebfluxDockerfile))
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, SpringWebFluxShell.WEB_FILTER, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.HANDLER_METHOD, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.HANDLER_FUNCTION, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.NETTY_HANDLER, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.WEB_FILTER, ShellTool.Command, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.HANDLER_METHOD, ShellTool.Command, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.HANDLER_FUNCTION, ShellTool.Command, Packers.Base64),
                arguments(imageName, SpringWebFluxShell.NETTY_HANDLER, ShellTool.Command, Packers.Base64)
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
        testShellInjectAssertOk(getUrl(container), Server.SpringWebFlux, shellType, shellTool, Opcodes.V17, packer);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
