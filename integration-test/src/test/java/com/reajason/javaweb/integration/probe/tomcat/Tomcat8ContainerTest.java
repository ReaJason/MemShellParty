package com.reajason.javaweb.integration.probe.tomcat;

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
public class Tomcat8ContainerTest {
    public static final String imageName = "tomcat:8-jre8";

    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(imageName)
            .withCopyToContainer(warFile, "/usr/local/tomcat/webapps/app.war")
            .waitingFor(Wait.forHttp("/app"))
            .withExposedPorts(8080);

    @Test
    void testJDK() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JRE|1.8.0_402|52", data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(
                Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"),
                data);
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
        ProbeAssertion.responseCommandIsOk(url, Server.Tomcat, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testScriptEngineReqHeaderResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseScriptEngineIsOk(url, Server.Tomcat, Opcodes.V1_8);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrl(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.Tomcat, Opcodes.V1_8);
        ProbeAssertion.responseBytecodeWithoutPrefixIsOk(url, Server.Tomcat, Opcodes.V1_8);
    }

    @Test
    void testFilterProbe() {
        String url = getUrl(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getTomcatFilterProbe());
        System.out.println(data);
        assertThat(data, anyOf(
                containsString("Context: ")
        ));
    }

    @Test
    void testFilterFirstInject() {
        String url = getUrl(container);
        shellInjectIsOk(url, Server.Tomcat, ShellType.FILTER, ShellTool.Command, Opcodes.V1_6, Packers.BigInteger, container);
        String data = VulTool.post(url + "/b64", DetectionTool.getTomcatFilterProbe());
        List<String> filter = ProbeAssertion.getFiltersForContext(data, "/app");
        String filterName = ProbeAssertion.extractFilterName(filter.get(0));
        assertThat(filterName, anyOf(startsWith(CommonUtil.getWebPackageNameForServer(Server.Tomcat))));
    }
}