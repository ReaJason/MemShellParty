package com.reajason.javaweb.integration.probe.tomcat;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.ShellAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.memshell.MemShellResult;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.probe.payload.FilterProbeFactory;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.objectweb.asm.Opcodes;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warJakartaFile;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Tomcat10ContainerTest {
    public static final String imageName = "tomcat:10.1.44-jre11";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warJakartaFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @AfterAll
    public static void tearDown() {
        log.info(container.getLogs());
    }

    @Test
    void testJDK() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JRE|11.0.28|55", data);
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
        assertEquals(Server.Tomcat, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseCommandIsOk(url, Server.Tomcat, Opcodes.V11);
    }

    @Test
    @SneakyThrows
    void testScriptEngineReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseScriptEngineIsOk(url, Server.Tomcat, Opcodes.V11);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.Tomcat, Opcodes.V11);
    }

    @Test
    void testFilterProbe() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(Server.Tomcat));
        ShellAssertion.assertFilterProbeIsRight(data);
    }

    @Test
    void testFilterFirstInject() {
        String url = getUrl(container);
        MemShellResult memShellResult = shellInjectIsOk(url, Server.Tomcat, ShellType.JAKARTA_FILTER, ShellTool.Command, Opcodes.V11, Packers.BigInteger, container);
        String data = VulTool.post(url + "/b64", DetectionTool.getTomcatFilterProbe());
        log.info(data);
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertEquals(filterName, memShellResult.getShellClassName());
    }
}
