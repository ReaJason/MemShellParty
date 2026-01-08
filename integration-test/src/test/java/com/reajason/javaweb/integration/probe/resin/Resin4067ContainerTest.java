package com.reajason.javaweb.integration.probe.resin;

import com.reajason.javaweb.Server;
import com.reajason.javaweb.integration.ProbeAssertion;
import com.reajason.javaweb.integration.VulTool;
import com.reajason.javaweb.integration.probe.DetectionTool;
import com.reajason.javaweb.memshell.ShellTool;
import com.reajason.javaweb.memshell.ShellType;
import com.reajason.javaweb.packer.Packers;
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
import java.util.List;

import static com.reajason.javaweb.integration.ContainerTool.getUrl;
import static com.reajason.javaweb.integration.ContainerTool.warFile;
import static com.reajason.javaweb.integration.ShellAssertion.shellInjectIsOk;
import static org.hamcrest.CoreMatchers.*;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/4
 */
@Slf4j
@Testcontainers
public class Resin4067ContainerTest {
    public static final String imageName = "reajason/resin:4.0.67-jdk11";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/resin4/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @Test
    void testJDK() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|11.0.16|55", data);
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
        assertEquals(Server.Resin, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseCommandIsOk(url, Server.Resin, Opcodes.V11);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.Resin, Opcodes.V11);
    }

    @Test
    void testFilterProbe() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getResinFilterProbe());
        System.out.println(data);
        assertThat(data, anyOf(
                containsString("Context: ")
        ));
    }

    @Test
    void testFilterFirstInject() {
        String url = getUrl(container);
        shellInjectIsOk(url, Server.Resin, ShellType.FILTER, ShellTool.Command, org.objectweb.asm.Opcodes.V1_6, Packers.BigInteger, container);
        String data = VulTool.post(url + "/b64", DetectionTool.getResinFilterProbe());
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertThat(filterName, anyOf(startsWith("com.caucho.server.dispatch.handlers")));
    }
}