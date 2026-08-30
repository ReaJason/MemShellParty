package com.reajason.javaweb.integration.memshell.tomcat;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
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
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2026/8/30
 */
@Slf4j
@Testcontainers
public class Tomcat8XSLTContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.XSLTScriptEngine)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}-xslt|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        ShellAssertion.shellInjectIsOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_8, packer, container);
    }
}
