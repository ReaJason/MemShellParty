package com.reajason.javaweb.integration.probe.weblogic;

import com.reajason.javaweb.Constants;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.memshell.Server;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;

import static com.reajason.javaweb.integration.ContainerTool.getUrlFromWebLogic;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
@Testcontainers
@Slf4j
public class WebLogic14110ContainerTest {
    public static final String imageName = "reajason/weblogic:14.1.1.0";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(7001);

    @Test
    void testJDK() {
        String url = getUrlFromWebLogic(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.8.0_391|52", data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrlFromWebLogic(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"), data);
    }

    @Test
    void testServerDetection() {
        String url = getUrlFromWebLogic(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getServerDetection());
        assertEquals(Constants.Server.WEBLOGIC, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrlFromWebLogic(container);
        ProbeAssertion.responseCommandIsOk(url, Constants.Server.WEBLOGIC, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrlFromWebLogic(container);
        ProbeAssertion.responseBytecodeIsOk(url, Constants.Server.WEBLOGIC, Opcodes.V1_8);
    }
}
