package com.reajason.javaweb.integration.springmvc;

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

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot2WarContainerTest {
    public static final String imageName = "tomcat:8-jre8";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(springBoot2WarFile, "/usr/local/tomcat/webapps/app.war")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.SpringWebMvc;
        List<String> supportedShellTypes = List.of(
                ShellType.SPRING_WEBMVC_INTERCEPTOR,
                ShellType.SPRING_WEBMVC_CONTROLLER_HANDLER
        );
        List<Packers> testPackers = List.of(Packers.ScriptEngine, Packers.SpEL, Packers.Base64);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.SpringWebMvc, shellType, shellTool, Opcodes.V1_8, packer, container, python);
    }
}
