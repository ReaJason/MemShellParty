package com.reajason.javaweb.integration.springmvc;

import com.reajason.javaweb.memshell.SpringMVCShell;
import com.reajason.javaweb.memshell.config.Server;
import com.reajason.javaweb.memshell.config.ShellTool;
import com.reajason.javaweb.memshell.packer.Packer;
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
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Behinder, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Behinder, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Behinder, Packer.INSTANCE.Base64),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Godzilla, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Godzilla, Packer.INSTANCE.Base64),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Command, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.INTERCEPTOR, ShellTool.Command, Packer.INSTANCE.Base64),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Behinder, Packer.INSTANCE.Base64),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Godzilla, Packer.INSTANCE.Base64),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Command, Packer.INSTANCE.ScriptEngine),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Command, Packer.INSTANCE.SpEL),
                arguments(imageName, SpringMVCShell.CONTROLLER_HANDLER, ShellTool.Command, Packer.INSTANCE.Base64)
        );
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
        testShellInjectAssertOk(getUrl(container), Server.SpringMVC, shellType, shellTool, Opcodes.V1_6, packer);
    }
}