package com.reajason.javaweb.integration.memshell.springwebmvc;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ContainerTool;
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
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot3ExpressionContainerTest {
    public static final String imageName = "springboot3";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>("eclipse-temurin:17.0.17_10-jdk")
            .withCopyFileToContainer(springBoot3JarFile, "/app/app.jar")
            .withCommand("java -jar /app/app.jar")
            .withCopyToContainer(jattachFile, "/jattach")
            .withCopyToContainer(springbootPid, "/fetch_pid.sh")
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);


    public static String getUrl(GenericContainer<?> container) {
        String host = container.getHost();
        int port = container.getMappedPort(8080);
        String url = "http://" + host + ":" + port;
        log.info("container started, app url is : {}", url);
        return url;
    }

    @AfterAll
    static void tearDown() {
        String logs = container.getLogs();
        log.info(logs);
//        assertThat("Logs should not contain any exceptions", logs, doesNotContainException());
    }

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Godzilla, Packers.SpELSpringGzipJDK17),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Godzilla, Packers.OGNLSpringGzipJDK17),
                arguments(imageName, ShellType.JAKARTA_VALVE, ShellTool.Godzilla, Packers.JXPathSpringGzipJDK17)
        );
    }

    @ParameterizedTest(name = "{0}-expression|{1}{2}|{3}")
    @MethodSource("casesProvider")
    void test(String imageName, String shellType, String shellTool, Packers packer) {
        ShellAssertion.shellInjectIsOk(getUrl(container), Server.Tomcat, shellType, shellTool, Opcodes.V17, packer, container);
    }
}
