package com.reajason.javaweb.integration.glassfish;

import com.reajason.javaweb.integration.TestCasesProvider;
import com.reajason.javaweb.memshell.Packers;
import com.reajason.javaweb.memshell.Server;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Triple;

import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class GlassFish3ContainerTest {
    public static final String imageName = "reajason/glassfish:3.1.2.2-jdk6";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/glassfish3/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .waitingFor(Wait.forLogMessage(".*(done|deployed).*", 1).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(8080);

    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/"));
    }

    static Stream<Arguments> casesProvider() {
        Server server = Server.GlassFish;
        List<String> supportedShellTypes = List.of(ShellType.FILTER, ShellType.LISTENER, ShellType.VALVE, ShellType.AGENT_FILTER_CHAIN, ShellType.CATALINA_AGENT_CONTEXT_VALVE);
        List<Packers> testPackers = List.of(Packers.JSP, Packers.JSPX, Packers.JavaDeserialize);
        List<Triple<String, ShellTool, Packers>> unSupportedCases = List.of(
                Triple.of(ShellType.CATALINA_AGENT_CONTEXT_VALVE, ShellTool.Godzilla, Packers.AgentJar),  // ClassFormatError
                Triple.of(ShellType.AGENT_FILTER_CHAIN, ShellTool.Godzilla, Packers.AgentJar) // ClassFormatError
        );
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers, unSupportedCases);
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
//        log.info(logs);
//        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
