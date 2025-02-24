package com.reajason.javaweb.integration.xxljob;

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
 * @since 2025/1/22
 */
@Testcontainers
@Slf4j
public class XxlJob220ContainerTest {

    public static final String imageName = "xxljob/xxljob220";

    @Container
    public static final DockerComposeContainer<?> compose =
            new DockerComposeContainer<>(new File("docker-compose/xxl-job/docker-compose-220.yaml"))
                    .withExposedService("executor", 9999);

    static Stream<Arguments> casesProvider() {
        Server server = Server.XXLJOB;
        List<String> supportedShellTypes = List.of(ShellType.NETTY_HANDLER);
        List<Packers> testPackers = List.of(Packers.XxlJob);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
    }

    @AfterAll
    static void tearDown() {
        String logs = compose.getContainerByServiceName("executor").get().getLogs();
        log.info("container stopped, logs is : {}", logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(), Server.XXLJOB, shellType, shellTool, Opcodes.V1_8, packer);
    }

    public static String getUrl() {
        String host = compose.getServiceHost("executor", 9999);
        int port = compose.getServicePort("executor", 9999);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
