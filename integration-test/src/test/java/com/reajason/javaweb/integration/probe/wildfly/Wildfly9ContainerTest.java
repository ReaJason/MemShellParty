package com.reajason.javaweb.integration.probe.wildfly;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * <a href="https://hub.docker.com/r/jboss/wildfly/tags">Wildfly - DockerHub</a>
 * <a href="https://quay.io/repository/wildfly/wildfly?tab=tags">Wildfly - Quay</a>
 *
 * @author ReaJason
 * @since 2024/12/10
 */
@Slf4j
@Testcontainers
public class Wildfly9ContainerTest {
    public static final String imageName = "jboss/wildfly:10.0.0.Final";
    @Container
    public static final GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/opt/jboss/wildfly/standalone/deployments/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @Test
    void testJDK() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.8.0_191|52", data);
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
        assertEquals(Server.Undertow, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseCommandIsOk(url, Server.Undertow, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.Undertow, Opcodes.V1_8);
    }
}
