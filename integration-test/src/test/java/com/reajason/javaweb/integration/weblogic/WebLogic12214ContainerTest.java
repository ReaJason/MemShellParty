package com.reajason.javaweb.integration.weblogic;

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
 * @since 2024/12/24
 */
@Testcontainers
@Slf4j
public class WebLogic12214ContainerTest {
    public static final String imageName = "reajason/weblogic:12.2.1.4";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(weblogicPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(7001);

    static Stream<Arguments> casesProvider() {
        Server server = Server.WebLogic;
        List<String> supportedShellTypes = List.of(
                ShellType.SERVLET, ShellType.FILTER, ShellType.LISTENER,
                ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT
        );
        List<Packers> testPackers = List.of(Packers.Base64);
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
        testShellInjectAssertOk(getUrl(container), Server.WebLogic, shellType, shellTool, Opcodes.V1_6, packer, container, python);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(7001);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
