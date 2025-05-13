package com.reajason.javaweb.integration.jetty;

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
import org.testcontainers.containers.DockerComposeContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.File;
import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
@Slf4j
@Testcontainers
public class Jetty12ee10ContainerTest {
    public static final String imageName = "jetty:12.0-jre21-ee10";
    public static final String serviceName = "jetty1221ee10";

    @Container
    public static final DockerComposeContainer<?> compose =
            new DockerComposeContainer<>(new File("docker-compose/jetty/docker-compose-12-jre21-ee10.yaml"))
                    .withExposedService(serviceName, 8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.Jetty;
        List<String> supportedShellTypes = List.of(
                ShellType.JAKARTA_SERVLET,
                ShellType.JAKARTA_FILTER,
                ShellType.JAKARTA_LISTENER
        );
        List<Packers> testPackers = List.of(Packers.Base64);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers,
                null, List.of(ShellTool.AntSword, ShellTool.NeoreGeorg) // AntSword not supported Jakarta
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = compose.getContainerByServiceName(serviceName).get().getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    public static String getUrl() {
        String host = compose.getServiceHost(serviceName, 8080);
        int port = compose.getServicePort(serviceName, 8080);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(), Server.Jetty, shellType, shellTool, Opcodes.V21, packer, null);
    }
}
