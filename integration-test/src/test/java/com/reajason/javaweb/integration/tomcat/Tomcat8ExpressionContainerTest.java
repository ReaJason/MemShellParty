package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.memshell.Server;
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
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Tomcat8ExpressionContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warExpressionFile, "/usr/local/tomcat/webapps/app.war")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(tomcatPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.EL),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.OGNLScriptEngine),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.OGNLSpringUtils),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.OGNLSpringIOUtils),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.MVEL),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.SpELScriptEngine),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.SpELSpringUtils),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.SpELSpringIOUtils),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JEXL),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JXPath),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Aviator),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.BeanShell),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Groovy),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Rhino),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.JinJava),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Freemarker),
                arguments(imageName, ShellType.FILTER, ShellTool.Godzilla, Packers.Velocity)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}-expression|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        testShellInjectAssertOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_8, packer, container);
    }
}