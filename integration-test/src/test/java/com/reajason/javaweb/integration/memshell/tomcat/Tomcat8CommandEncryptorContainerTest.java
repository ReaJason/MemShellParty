package com.reajason.javaweb.integration.memshell.tomcat;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
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
import org.testcontainers.shaded.org.apache.commons.lang3.RandomStringUtils;
import org.testcontainers.shaded.org.apache.commons.lang3.tuple.Pair;

import java.util.Base64;
import java.util.stream.Stream;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static com.reajason.javaweb.integration.DoesNotContainExceptionMatcher.doesNotContainException;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/**
 * @author ReaJason
 * @since 2025/4/28
 */
@Testcontainers
@Slf4j
public class Tomcat8CommandEncryptorContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    static Stream<Arguments> casesProvider() {
        return Stream.of(
                arguments(imageName, ShellType.FILTER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.LISTENER, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.PROXY_VALVE, ShellTool.Command, Packers.JSP),
                arguments(imageName, ShellType.WEBSOCKET, ShellTool.Command, Packers.JSP)
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
    void test(String imageName, String shellType, ShellTool shellTool, Packers packer) {
        String url = getUrl(container);

        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();

        String uniqueName = shellTool + RandomStringUtils.randomAlphabetic(5) + shellType + RandomStringUtils.randomAlphabetic(5) + packer.name();

        ShellToolConfig shellToolConfig = CommandConfig.builder()
                .paramName(uniqueName)
                .encryptor(CommandConfig.Encryptor.DOUBLE_BASE64)
                .build();

        MemShellResult generateResult = ShellAssertion.generate(urlPattern, Server.Tomcat, shellType, shellTool, Opcodes.V1_8, shellToolConfig, packer);

        ShellAssertion.packerResultAndInject(generateResult, url, shellTool, shellType, packer, container);

        String payload = Base64.getEncoder().encodeToString(Base64.getEncoder().encode("id".getBytes()));
        if (shellType.endsWith(ShellType.WEBSOCKET)) {
            ShellAssertion.webSocketCommandIsOk(shellUrl, payload);
        } else {
            ShellAssertion.commandIsOk(shellUrl, ((CommandConfig) generateResult.getShellToolConfig()), payload);
        }
    }
}
