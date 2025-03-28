package com.reajason.javaweb.integration.wildfly;

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
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Triple;

import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * <a href="https://hub.docker.com/r/jboss/wildfly/tags">Wildfly - DockerHub</a>
 * <a href="https://quay.io/repository/wildfly/wildfly?tab=tags">Wildfly - Quay</a>
 *
 * @author ReaJason
 * @since 2024/12/10
 */
@Slf4j
@Testcontainers
public class Wildfly9ContainerTest {
    public static final String imageName = "jboss/wildfly:10.0.0.Final";
    static Network network = Network.newNetwork();
    @Container
    public final static GenericContainer<?> python = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(neoGeorgDockerfile))
            .withNetwork(network);
    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/opt/jboss/wildfly/standalone/deployments/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(jbossPid, "/fetch_pid.sh")
            .withNetwork(network)
            .withNetworkAliases("app")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.Undertow;
        List<String> supportedShellTypes = List.of(
                ShellType.SERVLET, ShellType.FILTER, ShellType.LISTENER,
                ShellType.UNDERTOW_AGENT_SERVLET_HANDLER,
                ShellType.UNDERTOW_AGENT_SERVLET_HANDLER_ASM
        );
        List<Packers> testPackers = List.of(Packers.JSP, Packers.JSPX, Packers.ScriptEngine);
        List<Triple<String, ShellTool, Packers>> unSupportedCases = List.of(
                Triple.of(ShellType.UNDERTOW_AGENT_SERVLET_HANDLER, ShellTool.AntSword, Packers.AgentJar)  // Request ClassNotFound in module
        );
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, unSupportedCases);
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.Undertow, shellType, shellTool, Opcodes.V1_6, packer, container, python);
    }
}
