package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.integration.TestCasesProvider;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
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
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot3ContainerTest {
    public static final String imageName = "springboot3";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(springBoot3Dockerfile))
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(springbootPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        String server = Server.SpringWebMvc;
        List<String> supportedShellTypes = List.of(
                ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR,
                ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER,
                ShellType.SPRING_WEBMVC_AGENT_FRAMEWORK_SERVLET
        );
        List<Packers> testPackers = List.of(Packers.Base64, Packers.H2);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, null, List.of(ShellTool.AntSword));
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        shellInjectIsOk(getUrl(container), Server.SpringWebMvc, shellType, shellTool, Opcodes.V17, packer, container, python);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }

    static Stream<Arguments> tomcatCasesProvider() {
        String server = Server.Tomcat;
        List<String> supportedShellTypes = List.of(
                ShellType.JAKARTA_FILTER,
//                ShellType.LISTENER,
                ShellType.JAKARTA_VALVE,
                ShellType.JAKARTA_WEBSOCKET,
                ShellType.AGENT_FILTER_CHAIN,
                ShellType.CATALINA_AGENT_CONTEXT_VALVE
        );
        List<Packers> testPackers = List.of(Packers.H2);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, null, List.of(ShellTool.AntSword));
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("tomcatCasesProvider")
    void testTomcat(String imageName, String shellType, String shellTool, Packers packer) {
        shellInjectIsOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V17, packer, container, python);
    }


    @ParameterizedTest
    @ValueSource(strings = {ShellType.SPRING_WEBMVC_JAKARTA_INTERCEPTOR,
            ShellType.SPRING_WEBMVC_JAKARTA_CONTROLLER_HANDLER,})
    void testProbeInject(String shellType) {
        String url = getUrl(container);
        ShellAssertion.testProbeInject(url, Server.SpringWebMvc, shellType, Opcodes.V17);
    }
}
