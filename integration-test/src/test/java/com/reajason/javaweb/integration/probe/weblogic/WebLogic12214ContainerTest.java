package com.reajason.javaweb.integration.probe.weblogic;

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
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.List;

import static com.reajason.javaweb.integration.ContainerTool.getUrlFromWebLogic;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/24
 */
@Testcontainers
@Slf4j
public class WebLogic12214ContainerTest {
    public static final String imageName = "reajason/weblogic:12.2.1.4";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/u01/oracle/user_projects/domains/domain1/autodeploy/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(7001);

    @AfterAll
    public static void tearDown() {
        System.out.println(container.getLogs());
    }

    @Test
    void testJDK() {
        String url = getUrlFromWebLogic(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.8.0_411|52", data);
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
        assertEquals(Server.WebLogic, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrlFromWebLogic(container);
        ProbeAssertion.responseCommandIsOk(url, Server.WebLogic, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrlFromWebLogic(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.WebLogic, Opcodes.V1_8);
    }

    @Test
    void testFilterProbe() {
        String url = getUrlFromWebLogic(container);
        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(Server.WebLogic));
        ShellAssertion.assertFilterProbeIsRight(data);
    }

    @Test
    void testFilterFirstInject() {
        String url = getUrlFromWebLogic(container);
        MemShellResult memShellResult = shellInjectIsOk(url, Server.WebLogic, ShellType.FILTER, ShellTool.Command, org.objectweb.asm.Opcodes.V1_6, Packers.BigInteger, container);
        String data = VulTool.post(url + "/b64", FilterProbeFactory.getBase64ByServer(Server.WebLogic));
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertEquals(filterName, memShellResult.getShellClassName());
    }
}
