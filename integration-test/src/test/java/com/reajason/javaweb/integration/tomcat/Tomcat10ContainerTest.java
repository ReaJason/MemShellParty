package com.reajason.javaweb.integration.tomcat;

import com.reajason.javaweb.config.Server;
import com.reajason.javaweb.config.ShellTool;
import com.reajason.javaweb.memsell.packer.Packer;
import com.reajason.javaweb.memsell.tomcat.TomcatShell;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warJakartaFile;
import static com.reajason.javaweb.integration.ShellAssertionTool.testShellInjectAssertOk;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
public class Tomcat10ContainerTest {
    public static final String imageName = "tomcat:10.1-jre11";

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, TomcatShell.JAKARTA_FILTER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.JAKARTA_FILTER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.JAKARTA_LISTENER, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.JAKARTA_LISTENER, ShellTool.Command, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.JAKARTA_VALVE, ShellTool.Godzilla, Packer.INSTANCE.JSP),
                arguments(imageName, TomcatShell.JAKARTA_VALVE, ShellTool.Command, Packer.INSTANCE.JSP)
        );
    }

    @Container
    public final static GenericContainer<?> tomcat = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @ParameterizedTest(name = "{0}|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, ShellTool shellTool, Packer.INSTANCE packer) {
        testShellInjectAssertOk(getUrl(tomcat), Server.TOMCAT, shellType, shellTool, Opcodes.V11, packer);
    }
}