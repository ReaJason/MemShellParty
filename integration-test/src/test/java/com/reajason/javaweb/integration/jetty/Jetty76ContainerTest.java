package com.reajason.javaweb.integration.jetty;

import com.reajason.javaweb.config.Constants;
import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.Packer;
import net.bytebuddy.jar.asm.Opcodes;
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
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/7
 */
@Testcontainers
public class Jetty76ContainerTest {
    public static final String imageName = "reajason/jetty:7.6-jdk6";

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, Constants.FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, Constants.LISTENER, ShellTool.Command, Packer.INSTANCE.JSP)
        );
    }

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/jetty/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);


    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
        testShellInjectAssertOk(getUrl(container), Server.JETTY, shellType, shellTool, Opcodes.V1_6, packer);
    }
}
