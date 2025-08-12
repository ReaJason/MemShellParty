package com.reajason.javaweb.integration.probe.glassfish;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static org.junit.jupiter.api.Assertions.assertEquals;

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
            .waitingFor(Wait.forLogMessage(".*(done|deployed).*", 1).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(8080);
    @BeforeAll
    static void setup() {
        container.waitingFor(Wait.forHttp("/app/"));
    }

    @Test
    void testJDK() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.6.0_45|50", data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"), data);
    }

    @Test
    void testServerDetection() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getServerDetection());
        assertEquals(Server.GlassFish, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseCommandIsOk(url, Server.GlassFish, Opcodes.V1_6);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.GlassFish, Opcodes.V1_6);
    }
}
