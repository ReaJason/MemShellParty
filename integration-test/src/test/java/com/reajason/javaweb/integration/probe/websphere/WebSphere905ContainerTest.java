package com.reajason.javaweb.integration.probe.websphere;

import com.reajason.javaweb.Constants;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.memshell.Server;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;

import static com.reajason.javaweb.integration.ContainerTool.*;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
@Slf4j
public class WebSphere905ContainerTest {
    public static final String imageName = "reajason/websphere:9.0.5.17";
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
        assertEquals("JDK|1.8.0_381|52", data);
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
        assertEquals(Constants.Server.WEBSPHERE, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrlFromWAS(container);
        ProbeAssertion.responseCommandIsOk(url, Constants.Server.WEBSPHERE, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrlFromWAS(container);
        ProbeAssertion.responseBytecodeIsOk(url, Constants.Server.WEBSPHERE, Opcodes.V1_8);
    }
}
