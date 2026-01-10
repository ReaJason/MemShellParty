package com.reajason.javaweb.integration.probe.websphere;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
import com.reajason.javaweb.utils.CommonUtil;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.bytebuddy.jar.asm.Opcodes;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.List;

import static com.reajason.javaweb.integration.ContainerTool.getUrlFromWAS;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/21
 */
@Testcontainers
@Slf4j
public class OpenLiberty20ContainerTest {
    public static final String imageName = "open-liberty:20.0.0.12-full-java8-openj9";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/config/dropins/app.war")
            .waitingFor(Wait.forHttp("/app/").forPort(9080).withStartupTimeout(Duration.ofMinutes(5)))
            .withExposedPorts(9080)
            .withPrivilegedMode(true);

    @AfterAll
    public static void tearDown() {
        System.out.println(container.getLogs());
    }

    @Test
    void testJDK() {
        String url = getUrlFromWAS(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JRE|1.8.0_292|52", data);
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

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrlFromWAS(container);
        ProbeAssertion.responseCommandIsOk(url, Server.WebSphere, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrlFromWAS(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.WebSphere, Opcodes.V1_8);
    }


    @Test
    void testFilterProbe() {
        String url = getUrlFromWAS(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getWebSphereFilterProbe());
        System.out.println(data);
        assertThat(data, anyOf(
                containsString("Context: ")
        ));
    }

    @Test
    void testFilterFirstInject() {
        String url = getUrlFromWAS(container);
        shellInjectIsOk(url, Server.WebSphere, ShellType.FILTER, ShellTool.Command, org.objectweb.asm.Opcodes.V1_6, Packers.BigInteger, container);
        String data = VulTool.post(url + "/b64", DetectionTool.getWebSphereFilterProbe());
        log.info(data);
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertThat(filterName, anyOf(startsWith(CommonUtil.getWebPackageNameForServer(Server.WebSphere))));
    }
}
