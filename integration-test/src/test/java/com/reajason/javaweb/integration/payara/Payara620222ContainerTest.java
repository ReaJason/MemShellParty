package com.reajason.javaweb.integration.payara;

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
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Set;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;

/**
 * @author ReaJason
 * @since 2024/12/12
 */
@Slf4j
@Testcontainers
public class Payara620222ContainerTest {
    public static final String imageName = "reajason/payara:6.2022.2-jdk11";

    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/usr/local/payara6/glassfish/domains/domain1/autodeploy/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(glassfishPid, "/fetch_pid.sh")
            .waitingFor(Wait.forLogMessage(".*JMXService.*", 1))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.Payara;
        Set<String> supportedShellTypes = Set.of(ShellType.JAKARTA_FILTER, ShellType.JAKARTA_LISTENER, ShellType.JAKARTA_VALVE,
                ShellType.AGENT_FILTER_CHAIN, ShellType.CATALINA_AGENT_CONTEXT_VALVE);
        Set<Packers> testPackers = Set.of(Packers.JSP, Packers.JSPX, Packers.JavaDeserialize);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers,
                null, Set.of(ShellTool.AntSword) // AntSword not supported Jakarta
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
        testShellInjectAssertOk(getUrl(container), Server.Payara, shellType, shellTool, Opcodes.V1_6, packer, container);
    }
}
