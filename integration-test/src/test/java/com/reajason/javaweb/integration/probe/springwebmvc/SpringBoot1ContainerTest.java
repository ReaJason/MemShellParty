package com.reajason.javaweb.integration.probe.springwebmvc;

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
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.file.Files;
import java.nio.file.Paths;

import static com.reajason.javaweb.integration.ContainerTool.getUrlFromSpringBoot;
import static com.reajason.javaweb.integration.ContainerTool.springBoot1Dockerfile;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * @author ReaJason
 * @since 2024/12/22
 */
@Testcontainers
@Slf4j
public class SpringBoot1ContainerTest {
    public static final String imageName = "springboot1";
    @Container
    public final static GenericContainer<?> container = new GenericContainer<>(new ImageFromDockerfile()
            .withDockerfile(springBoot1Dockerfile))
            .waitingFor(Wait.forHttp("/test"))
            .withExposedPorts(8080);

    @Test
    void testJDK() {
        String url = getUrlFromSpringBoot(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getJdkDetection());
        assertEquals("JDK|1.8.0_342|52", data);
    }

    @Test
    @SneakyThrows
    void testBasicInfo() {
        String url = getUrlFromSpringBoot(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getBasicInfoPrinter());
        Files.writeString(Paths.get("src", "test", "resources", "infos", this.getClass().getSimpleName() + "BasicInfo.txt"), data);
    }

    @Test
    void testServerDetection() {
        String url = getUrlFromSpringBoot(container);
        String data = VulTool.post(url + "/b64", DetectionTool.getServerDetection());
        assertEquals(Server.Tomcat, data);
    }

    @Test
    @SneakyThrows
    void testCommandReqHeaderResponseBody() {
        String url = getUrlFromSpringBoot(container);
        ProbeAssertion.responseCommandIsOk(url, Server.Tomcat, Opcodes.V1_6);
    }

    @Test
    @SneakyThrows
    void testBytecodeReqParamResponseBody() {
        String url = getUrlFromSpringBoot(container);
        ProbeAssertion.responseBytecodeIsOk(url, Server.Tomcat, Opcodes.V1_6);
    }
}