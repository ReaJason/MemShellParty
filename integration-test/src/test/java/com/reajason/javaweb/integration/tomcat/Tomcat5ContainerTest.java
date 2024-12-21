package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.memshell.TomcatShell;
import com.reajason.javaweb.memshell.config.Constants;
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
import static com.reajason.javaweb.integration.ContainerTool.warFile;
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
public class Tomcat5ContainerTest {
    public static final String imageName = "reajason/tomcat:5-jdk6";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.SERVLET, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Behinder, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Behinder, Packer.INSTANCE.Deserialize),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.VALVE, ShellTool.Command, Packer.INSTANCE.Deserialize)
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
        testShellInjectAssertOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V1_6, packer);
    }
}