package com.reajason.javaweb.integration.probe.websphere7;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;

import static com.reajason.javaweb.integration.ContainerTool.getUrlFromWAS;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
@Slf4j
public class WebSphere700ContainerTest {
    public static final String imageName = "reajason/websphere:7.0.0.21";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withFileSystemBind(warFile.getFilesystemPath(), "/opt/IBM/WebSphere/AppServer/profiles/AppSrv01/monitoredDeployableApps/servers/server1/app.war", BindMode.READ_WRITE)
            .waitingFor(Wait.forHttp("/app/").forPort(9080).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(9080)
            .withPrivilegedMode(true);

    @Test
    void testJDK() {
        String url = getUrlFromWAS(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.6.0|50", data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrlFromWAS(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"), data);
    }

    @Test
    void testServerDetection() {
        String url = getUrlFromWAS(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getServerDetection());
        assertEquals(Server.WebSphere, data);
    }
}
