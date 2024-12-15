package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
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

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warExpressionFile;
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
public class Tomcat8ContainerTest {
    public static final String imageName = "tomcat:8-jre8";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warExpressionFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.EL),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Ognl),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.SpEL),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Freemarker),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Velocity)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
        testShellInjectAssertOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_8, packer);
    }
}