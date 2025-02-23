package com.reajason.javaweb.integration.springmvc;

import com.reajason.javaweb.integration.TestCasesProvider;
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
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Set;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
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
public class SpringBoot3ContainerTest {
    public static final String imageName = "springboot3";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(springBoot3Dockerfile))
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(springbootPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.SpringWebMvc;
        Set<String> supportedShellTypes = Set.of(ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR, ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER, ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET);
        Set<Packers> testPackers = Set.of(Packers.Base64);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, null, Set.of(ShellTool.AntSword));
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.SpringWebMvc, shellType, shellTool, Opcodes.V17, packer, container);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }
}
