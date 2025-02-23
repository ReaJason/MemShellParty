package com.reajason.javaweb.integration.resin;

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
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Resin4067ContainerTest {
    public static final String imageName = "reajason/resin:4.0.67-jdk11";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/resin4/webapps/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(resinPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        Server server = Server.Resin;
        Set<String> supportedShellTypes = Set.of(ShellType.FILTER, ShellType.LISTENER, ShellType.AGENT_FILTER_CHAIN);
        Set<Packers> testPackers = Set.of(Packers.JSP, Packers.JSPX, Packers.JavaDeserialize);
        return TestCasesProvider.getTestCases(imageName, server, supportedShellTypes, testPackers);
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
        testShellInjectAssertOk(getUrl(container), Server.Resin, shellType, shellTool, Opcodes.V11, packer, container);
    }
}