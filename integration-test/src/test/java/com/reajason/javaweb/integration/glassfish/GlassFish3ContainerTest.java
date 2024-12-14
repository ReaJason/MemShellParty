package com.reajason.javaweb.integration.glassfish;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.glassfish.GlassFishShell;
import com.reajason.javaweb.memsell.packer.Packer;
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

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

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
            .waitingFor(Wait.forLogMessage(".*(JMXService|deployed).*", 1))
            .withExposedPorts(8080);

    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/"));
    }

    static Stream<Arguments> casesProvider() {
        return Stream.of(
//                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP), // java.lang.NoClassDefFoundError: java/lang/ReflectiveOperationException
//                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.Deserialize),
//                arguments(imageName, GlassFishShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.JSP), // Caused by: java.lang.ClassNotFoundException: javax.crypto.Cipher not found by org.glassfish.main.web.glue [222]
//                arguments(imageName, GlassFishShell.VALVE, ShellTool.Godzilla, Packer.INSTANCE.Deserialize),
                arguments(imageName, GlassFishShell.VALVE, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, GlassFishShell.VALVE, ShellTool.Command, Packer.INSTANCE.Deserialize)
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
        testShellInjectAssertOk(getUrl(container), Server.GlassFish, shellType, shellTool, Opcodes.V1_6, packer);
    }
}
