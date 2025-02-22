package com.reajason.javaweb.integration.weblogic;

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
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
@Testcontainers
@Slf4j
public class WebLogic12214ContainerTest {
    public static final String imageName = "reajason/weblogic:12.2.1.4";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(weblogicPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(7001);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.SERVLET, ShellTool.Behinder, Packers.Base64),
                arguments(imageName, ShellType.SERVLET, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, ShellType.SERVLET, ShellTool.Command, Packers.Base64),
                arguments(imageName, ShellType.SERVLET, ShellTool.Suo5, Packers.Base64),
                arguments(imageName, ShellType.SERVLET, ShellTool.AntSword, Packers.Base64),
                arguments(imageName, ShellType.FILTER, ShellTool.Behinder, Packers.Base64),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, ShellType.FILTER, ShellTool.Command, Packers.Base64),
                arguments(imageName, ShellType.FILTER, ShellTool.Suo5, Packers.Base64),
                arguments(imageName, ShellType.FILTER, ShellTool.AntSword, Packers.Base64),
                arguments(imageName, ShellType.LISTENER, ShellTool.Behinder, Packers.Base64),
                arguments(imageName, ShellType.LISTENER, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, ShellType.LISTENER, ShellTool.Command, Packers.Base64),
                arguments(imageName, ShellType.LISTENER, ShellTool.Suo5, Packers.Base64),
                arguments(imageName, ShellType.LISTENER, ShellTool.AntSword, Packers.Base64),
                arguments(imageName, ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT, ShellTool.AntSword, Packers.AgentJar),
                arguments(imageName, ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT, ShellTool.Command, Packers.AgentJar),
                arguments(imageName, ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT, ShellTool.Behinder, Packers.AgentJar),
                arguments(imageName, ShellType.WEBLOGIC_AGENT_SERVLET_CONTEXT, ShellTool.Godzilla, Packers.AgentJar)
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
        testShellInjectAssertOk(getUrl(container), Server.WebLogic, shellType, shellTool, Opcodes.V1_6, packer, container);
    }

    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(7001);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
