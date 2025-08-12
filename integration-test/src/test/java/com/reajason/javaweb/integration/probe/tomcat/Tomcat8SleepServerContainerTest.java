package com.reajason.javaweb.integration.probe.tomcat;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.probe.ProbeContent;
import com.reajason.javaweb.probe.ProbeMethod;
import com.reajason.javaweb.probe.ProbeShellGenerator;
import com.reajason.javaweb.probe.ProbeShellResult;
import com.reajason.javaweb.probe.config.ProbeConfig;
import com.reajason.javaweb.probe.config.SleepConfig;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import okhttp3.*;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static org.junit.jupiter.api.Assertions.*;

/**
 * @author ReaJason
 * @since 2025/8/12
 */
@Slf4j
@Testcontainers
public class Tomcat8SleepServerContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @Test
    void testSleepServerDetection() {
        String url = getUrl(container);
        assertFalse(sleepDetectionIsOk(url, Server.Jetty, Opcodes.V1_8) > 5_000_000_000L);
        assertTrue(sleepDetectionIsOk(url, Server.Tomcat, Opcodes.V1_8) > 5_000_000_000L);
    }

    @SneakyThrows
    public static long sleepDetectionIsOk(String url, String server, int targetJreVersion) {
        ProbeConfig probeConfig = ProbeConfig.builder()
                .probeMethod(ProbeMethod.Sleep)
                .probeContent(ProbeContent.Server)
                .debug(true)
                .shrink(true)
                .targetJreVersion(targetJreVersion)
                .build();
        SleepConfig sleepConfig = SleepConfig.builder()
                .server(server)
                .seconds(5)
                .build();
        ProbeShellResult probeResult = ProbeShellGenerator.generate(probeConfig, sleepConfig);
        String content = probeResult.getShellBytesBase64Str();
        RequestBody requestBody = new FormBody.Builder()
                .add("data", content)
                .build();
        Request request = new Request.Builder()
                .header("Content-Type", "application/x-www-form-urlencoded")
                .url(url + "/b64").post(requestBody)
                .build();
        long startTime = System.nanoTime();
        try (Response response = new OkHttpClient().newCall(request).execute()) {
            assertEquals(200, response.code());
            long endTime = System.nanoTime();
            return endTime - startTime;
        }
    }
}
