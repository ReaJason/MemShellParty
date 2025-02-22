package com.reajason.javaweb.integration.springmvc;

import com.reajason.javaweb.memshell.server.SpringWebMvcShell;
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

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.springBoot2WarFile;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot2WarContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(springBoot2WarFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Behinder, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Behinder, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Behinder, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Godzilla, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Command, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Command, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Command, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Suo5, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Suo5, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.INTERCEPTOR, ShellTool.Suo5, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Command, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Command, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Command, Packers.Base64),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Suo5, Packers.ScriptEngine),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Suo5, Packers.SpEL),
                arguments(imageName, SpringWebMvcShell.CONTROLLER_HANDLER, ShellTool.Suo5, Packers.Base64)
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
        testShellInjectAssertOk(getUrl(container), Server.SpringWebMvc, shellType, shellTool, Opcodes.V1_8, packer);
    }
}
